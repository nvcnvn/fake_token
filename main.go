package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

func main() {
	var (
		port          = os.Getenv("PORT")
		keysPattern   = os.Getenv("KEYS_PATTERN")
		tokenTemplate = os.Getenv("TOKEN_TEMPLATE")
	)

	keysMap := loadKeys(keysPattern)
	http.Handle("/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", newPublicKeyServer(keysMap))
	http.Handle("/token", newDummyTokenServer(tokenTemplate, keysMap))

	log.Println("Listening on PORT", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func loadKeys(folder string) map[string]*rsa.PrivateKey {
	matches, err := filepath.Glob("./private_pems/*.pem")
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
	publicKeysMap map[string]string
}

func newPublicKeyServer(keysMap map[string]*rsa.PrivateKey) *publicKeyServer {
	s := &publicKeyServer{}
	s.publicKeysMap = make(map[string]string, len(keysMap))
	for keyID, privateKey := range keysMap {
		asn1Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err)
		}

		s.publicKeysMap[keyID] = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}))
	}
	return s
}

func (s *publicKeyServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "max-age:86400, public")
	json.NewEncoder(resp).Encode(s.publicKeysMap)
}

type dummyTokenServer struct {
	tmpl    *template.Template
	keysMap map[string]*rsa.PrivateKey
}

func newDummyTokenServer(tmplFile string, keysMap map[string]*rsa.PrivateKey) *dummyTokenServer {
	return &dummyTokenServer{
		tmpl:    template.Must(template.ParseFiles(tmplFile)),
		keysMap: keysMap,
	}
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
func (s *dummyTokenServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	tokenValue := struct {
		IssuerPrefix string
		Audience     string
		AuthTime     string
		UserID       string
		IssueAt      string
		Expiration   string
		PhoneNumber  string
	}{
		IssuerPrefix: req.FormValue("IssuerPrefix"),
		Audience:     req.FormValue("Audience"),
		AuthTime:     req.FormValue("AuthTime"),
		UserID:       req.FormValue("UserID"),
		IssueAt:      req.FormValue("IssueAt"),
		Expiration:   req.FormValue("Expiration"),
		PhoneNumber:  req.FormValue("PhoneNumber"),
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

	var buff bytes.Buffer
	s.tmpl.Execute(&buff, &tokenValue)

	kid, key := s.selectKey(req.FormValue("kid"))
	header := &jws.StandardHeaders{}
	header.Set("kid", kid)
	k, err := jws.Sign(buff.Bytes(), jwa.RS256, key, jws.WithHeaders(header))
	if err != nil {
		log.Println(err)
	}
	resp.Write(k)
}
