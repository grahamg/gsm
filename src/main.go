package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type Secret struct {
	Key      string   `json:"key"`
	Value    string   `json:"value"`
	Tags     []string `json:"tags,omitempty"`
	Archived bool     `json:"archived,omitempty"`
}

type Safe struct {
	Name    string   `json:"name"`
	Secrets []Secret `json:"secrets,omitempty"`
}

var openSafes = make(map[string]Safe)
var mutex = &sync.Mutex{}

func main() {
	http.HandleFunc("/api/v1/safe/open", handleOpenSafe)
	http.HandleFunc("/api/v1/safe/create", handleCreateSafe)
	http.HandleFunc("/api/v1/safe/export", handleExportSafe)
	http.HandleFunc("/api/v1/safe/hash", handleHashSafe)
	http.HandleFunc("/api/v1/safe/entry", handleUpdateSecret)
	http.HandleFunc("/api/v1/safe/archive", handleArchiveSecret)
	http.HandleFunc("/api/v1/safe/unarchive", handleUnarchiveSecret)
	http.HandleFunc("/api/v1/safe/tag", handleAddTag)
	http.HandleFunc("/api/v1/safe/tag", handleRemoveTag)
	http.HandleFunc("/api/v1/gsm/about", handleTeapot)

	fmt.Println("Starting GSM server on port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func handleOpenSafe(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := openSafes[safeName]; ok {
		http.Error(w, "Safe already open", http.StatusBadRequest)
		return
	}
	password := os.Getenv("GSM_PASSWORD")
	if password == "" {
		http.Error(w, "Missing password", http.StatusBadRequest)
		return
	}
	cmd := exec.Command("openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-in", safeName+".txt.enc", "-k", password)
	data, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error decrypting safe: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var safe Safe
	err = json.Unmarshal(data, &safe)
	if err != nil {
		http.Error(w, "Error decoding safe: "+err.Error(), http.StatusInternalServerError)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleCreateSafe(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := openSafes[safeName]; ok {
		http.Error(w, "Safe already open", http.StatusBadRequest)
		return
	}
	safe := Safe{Name: safeName}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleExportSafe(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	data, err := json.Marshal(safe)
	if err != nil {
		http.Error(w, "Error encoding safe: "+err.Error(), http.StatusInternalServerError)
		return
	}
	password := os.Getenv("GSM_PASSWORD")
	if password == "" {
		http.Error(w, "Missing password", http.StatusBadRequest)
		return
	}
	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-salt", "-in", "-", "-out", safe.Name+".txt.enc", "-k", password)
	cmd.Stdin = strings.NewReader(string(data))
	err = cmd.Run()
	if err != nil {
		http.Error(w, "Error encrypting safe: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+safe.Name+".txt.enc")
	file, err := os.Open(safe.Name + ".txt.enc")
	if err != nil {
		http.Error(w, "Error opening encrypted file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading encrypted file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(fileContents)
}

func handleHashSafe(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%v", safe)))
	fmt.Fprintln(w, fmt.Sprintf("%x", hash))
	w.WriteHeader(http.StatusOK)
}

func handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}
	var secret Secret
	err := json.NewDecoder(r.Body).Decode(&secret)
	if err != nil {
		http.Error(w, "Error decoding secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for i, s := range safe.Secrets {
		if s.Key == key {
			secret.Archived = s.Archived
			safe.Secrets[i] = secret
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Secret not found", http.StatusBadRequest)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleArchiveSecret(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}
	found := false
	for i, s := range safe.Secrets {
		if s.Key == key {
			s.Archived = true
			safe.Secrets[i] = s
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Secret not found", http.StatusBadRequest)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)

}

func handleUnarchiveSecret(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}
	found := false
	for i, s := range safe.Secrets {
		if s.Key == key {
			s.Archived = false
			safe.Secrets[i] = s
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Secret not found", http.StatusBadRequest)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleAddTag(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}
	var tag string
	err := json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Error decoding tag: "+err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for i, s := range safe.Secrets {
		if s.Key == key {
			s.Tags = append(s.Tags, tag)
			safe.Secrets[i] = s
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Secret not found", http.StatusBadRequest)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleRemoveTag(w http.ResponseWriter, r *http.Request) {
	safeName := r.URL.Query().Get("as")
	if safeName == "" {
		http.Error(w, "Missing safe name", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	safe, ok := openSafes[safeName]
	if !ok {
		http.Error(w, "Safe not open", http.StatusBadRequest)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}
	var tag string
	err := json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Error decoding tag: "+err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for i, s := range safe.Secrets {
		if s.Key == key {
			for j, t := range s.Tags {
				if t == tag {
					s.Tags = append(s.Tags[:j], s.Tags[j+1:]...)
					safe.Secrets[i] = s
					found = true
					break
				}
			}
			break
		}
	}
	if !found {
		http.Error(w, "Secret or tag not found", http.StatusBadRequest)
		return
	}
	openSafes[safeName] = safe
	w.WriteHeader(http.StatusOK)
}

func handleTeapot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is GSM, Git/Go/Graham Secret Management")
	fmt.Fprintln(w, "Version: 1.0.0")
	fmt.Fprintln(w, "Author: Graham Wihlidal")
	fmt.Fprintln(w, "License: Apache 2.0")
	fmt.Fprintln(w, "Source: https://github.com/grahamwihlidal/gsm")
	w.WriteHeader(http.StatusTeapot)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/safe/open", handleOpenSafe).Methods("GET")
	r.HandleFunc("/api/v1/safe/create", handleCreateSafe).Methods("POST")
	r.HandleFunc("/api/v1/safe/export", handleExportSafe).Methods("GET")
	r.HandleFunc("/api/v1/safe/hash", handleHashSafe).Methods("GET")
	r.HandleFunc("/api/v1/safe/entry", handleUpdateSecret).Methods("PUT")
	r.HandleFunc("/api/v1/safe/entry", handleUpdateSecret).Methods("PATCH")
	r.HandleFunc("/api/v1/safe/archive", handleArchiveSecret).Methods("PATCH")
	r.HandleFunc("/api/v1/safe/unarchive", handleUnarchiveSecret).Methods("PATCH")
	r.HandleFunc("/api/v1/safe/tag", handleAddTag).Methods("PUT")
	r.HandleFunc("/api/v1/safe/tag", handleRemoveTag).Methods("DELETE")
	r.HandleFunc("/about", handleTeapot).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))
}
