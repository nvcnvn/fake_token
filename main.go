package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func main() {
	var (
		port          = os.Getenv("PORT")
		keysGlob      = os.Getenv("KEYS_GLOB")
		tmplsGlob     = os.Getenv("TEMPLATES_GLOB")
		certNotBefore = os.Getenv("CERT_NOT_BEFORE")
		certNotAfter  = os.Getenv("CERT_NOT_AFTER")
	)

	keysMap := loadKeys(keysGlob)

	sv := newDummyTokenServer(tmplsGlob, keysMap)

	http.HandleFunc("/token", sv.FakeToken)
	http.HandleFunc("/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", newPublicKeyServer(keysMap, certNotBefore, certNotAfter).ServeHTTP)
	http.HandleFunc("/jwkset", sv.ServeJWKSet(keysGlob))

	log.Println("Listening on PORT", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func loadKeys(keysGlob string) map[string]*rsa.PrivateKey {
	matches, err := filepath.Glob(keysGlob)
	if err != nil {
		log.Fatal(err)
	}

	keys := make(map[string]*rsa.PrivateKey, len(matches))
	for _, name := range matches {
		b, err := ioutil.ReadFile(name)
		if err != nil {
			log.Fatal(err)
		}

		block, _ := pem.Decode(b)
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		h := sha1.New()
		h.Write(block.Bytes)
		keys[fmt.Sprintf("%x", h.Sum(nil))] = privateKey
	}

	return keys
}

type publicKeyServer struct {
	certsMap map[string]string
}

func newPublicKeyServer(keysMap map[string]*rsa.PrivateKey, certNotBefore, certNotAfter string) *publicKeyServer {
	s := &publicKeyServer{}
	s.certsMap = make(map[string]string, len(keysMap))
	for keyID, privateKey := range keysMap {

		notBefore, err := time.Parse("Jan 2 15:04:05 2006", certNotBefore)

		notAfter, err := time.Parse("Jan 2 15:04:05 2006", certNotAfter)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("failed to generate serial number: %s", err)
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}

		s.certsMap[keyID] = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}))
	}
	return s
}

func (s *publicKeyServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "public, max-age=86400, must-revalidate, no-transform")
	json.NewEncoder(resp).Encode(s.certsMap)
}

type TokenPayloadClaims struct {
	IssuerPrefix string
	Audience     string
	AuthTime     string
	UserID       string
	IssueAt      string
	Expiration   string
	PhoneNumber  string
	SchoolIDs    []string
}

func (t *TokenPayloadClaims) ConvertSchoolIDsToHtml() template.HTML {
	if t.SchoolIDs == nil || len(t.SchoolIDs) == 0 {
		return "[]"
	}
	bytes, err := json.Marshal(t.SchoolIDs)
	if err != nil {
		return "[]"
	}
	return template.HTML(bytes)
}

type dummyTokenServer struct {
	tmpls   map[string]*template.Template
	keysMap map[string]*rsa.PrivateKey
}

func newDummyTokenServer(tmplsGlob string, keysMap map[string]*rsa.PrivateKey) *dummyTokenServer {
	names, err := filepath.Glob(tmplsGlob)
	if err != nil {
		panic(err)
	}

	s := &dummyTokenServer{
		tmpls:   make(map[string]*template.Template),
		keysMap: keysMap,
	}

	for _, n := range names {
		fmt.Println(n)
		s.tmpls[n] = template.Must(template.ParseFiles(n))
	}

	return s
}

func (s *dummyTokenServer) selectKey(id string) (string, *rsa.PrivateKey) {
	key, ok := s.keysMap[id]
	if ok {
		return id, key
	}

	for id, key := range s.keysMap {
		return id, key
	}

	return "", nil
}

func (s *dummyTokenServer) FakeToken(resp http.ResponseWriter, req *http.Request) {

	err:=req.ParseForm()
	if err != nil {
		return
	}

	arrSchoolIDs :=req.Form["SchoolIDs"]

	tokenValue := TokenPayloadClaims{
		IssuerPrefix: req.FormValue("IssuerPrefix"),
		Audience:     req.FormValue("Audience"),
		AuthTime:     req.FormValue("AuthTime"),
		UserID:       req.FormValue("UserID"),
		IssueAt:      req.FormValue("IssueAt"),
		Expiration:   req.FormValue("Expiration"),
		PhoneNumber:  req.FormValue("PhoneNumber"),
		SchoolIDs:    arrSchoolIDs,
	}

	now := time.Now()
	if tokenValue.AuthTime == "" {
		tokenValue.AuthTime = strconv.FormatInt(now.Add(-1*time.Minute).Unix(), 10)
	}

	if tokenValue.IssueAt == "" {
		tokenValue.IssueAt = strconv.FormatInt(now.Unix(), 10)
	}

	if tokenValue.Expiration == "" {
		tokenValue.Expiration = strconv.FormatInt(now.Add(1*time.Hour).Unix(), 10)
	}

	if tokenValue.UserID == "" {
		tokenValue.UserID = strconv.FormatInt(now.UnixNano(), 10)
	}

	if tokenValue.PhoneNumber == "" {
		tokenValue.PhoneNumber = strconv.FormatInt(now.Unix(), 10)
	}

	tmpl, ok := s.tmpls[req.FormValue("template")]
	if !ok {
		return
	}

	var buff bytes.Buffer
	tmpl.Execute(&buff, &tokenValue)

	kid, key := s.selectKey(req.FormValue("kid"))
	header := &jws.StandardHeaders{}
	header.Set("kid", kid)
	k, err := jws.Sign(buff.Bytes(), jwa.RS256, key, jws.WithHeaders(header))
	if err != nil {
		log.Println(err)
	}
	resp.Write(k)
}

func (s *dummyTokenServer) ServeJWKSet(path string) func(w http.ResponseWriter, req *http.Request) {
	set := jwk.Set{
		Keys: []jwk.Key{},
	}

	keysMap := loadKeys(path)
	for keyID, privateKey := range keysMap {
		set.Keys = append(set.Keys, convertJWK(privateKey, keyID))
	}

	header := &jws.StandardHeaders{}
	header.Set(jwk.KeyIDKey, set.Keys[0].KeyID())

	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&set)
	}
}

func convertJWK(privateKey *rsa.PrivateKey, id string) jwk.Key {
	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	key.Set(jwk.KeyIDKey, id)
	key.Set(jwk.KeyUsageKey, "sig")
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	return key
}

