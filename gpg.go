package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

func verifyOnlineDocument(res http.ResponseWriter, r *http.Request) {
	document, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || len(r.URL.Query().Get("url")) == 0 {
		http.Error(res, "Invalid url parameter specified", http.StatusInternalServerError)
		return
	}

	tmpDir, err := ioutil.TempDir("", "keyring")
	if err != nil {
		http.Error(res, "Unable to create keyring", http.StatusInternalServerError)
		return
	}
	keyringFile := path.Join(tmpDir, "keyring.gpg")

	filename := path.Base(document.Path)

	keyID := r.URL.Query().Get("key")
	keyURL := r.URL.Query().Get("key-url")
	if err := primeGPGTrustedStore(keyID, keyURL, keyringFile); err != nil {
		if err := renderBadge(res, verificationStatusError, filename, time.Now(), err.Error(), ""); err != nil {
			http.Error(res, "Unable to render: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	doc, signature, err := downloadDocumentAndSignature(r.URL.Query().Get("url"))
	if err != nil {
		if err := renderBadge(res, verificationStatusError, filename, time.Now(), err.Error(), ""); err != nil {
			http.Error(res, "Unable to render: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	result, key, err := verifySignature(doc, signature, keyringFile)
	if err != nil {
		if err := renderBadge(res, result, filename, time.Now(), err.Error(), ""); err != nil {
			http.Error(res, "Unable to render: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	os.RemoveAll(tmpDir)

	if err := renderBadge(res, result, filename, time.Now(), "", key); err != nil {
		http.Error(res, "Unable to render: "+err.Error(), http.StatusInternalServerError)
	}
}

func primeGPGTrustedStore(keyID, keyURL, keyringFile string) error {
	if len(keyID) == 0 {
		return fmt.Errorf("Paramter key was empty")
	}

	if len(keyURL) == 0 {
		keyURL = "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + keyID
	}

	resp, err := http.Get(keyURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	cmd := exec.Command(cfg.GPGPath,
		"--no-default-keyring",
		"--batch",
		"--keyring", keyringFile,
		"--keyserver-options", "no-auto-key-retrieve",
		"--import",
	)
	cmd.Stdin = resp.Body
	cmd.Run()

	return nil
}

func verifySignature(document, signature []byte, keyringFile string) (verificationStatus, string, error) {
	tmpDir, err := ioutil.TempDir("", "pgp_verify")
	if err != nil {
		return verificationStatusError, "", err
	}

	err = ioutil.WriteFile(path.Join(tmpDir, "document"), document, 0600)
	if err != nil {
		return verificationStatusError, "", err
	}

	err = ioutil.WriteFile(path.Join(tmpDir, "document.asc"), signature, 0600)
	if err != nil {
		return verificationStatusError, "", err
	}

	cmd := exec.Command(cfg.GPGPath,
		"--no-default-keyring",
		"--batch",
		"--keyring", keyringFile,
		"--keyserver-options", "no-auto-key-retrieve",
		"--verify", path.Join(tmpDir, "document.asc"),
		path.Join(tmpDir, "document"),
	)
	out := bytes.NewBuffer([]byte{})
	cmd.Stderr = out
	cmd.Stdout = out

	err = cmd.Run()

	os.RemoveAll(tmpDir)

	key := ""
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "Signature made") {
			t := strings.Split(line, " ")
			key = t[len(t)-1]
		}
	}

	if err != nil {
		log.Printf(out.String())
		return verificationStatusFailed, "", err
	}

	return verificationStatusOK, key, nil
}

func downloadDocumentAndSignature(documentURL string) ([]byte, []byte, error) {
	doc, err := downloadDocument(documentURL)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	sig, err := downloadDocument(documentURL + ".asc")
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return doc, sig, nil
}

func downloadDocument(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []byte{}, fmt.Errorf("StatusCode for %s was != 200: %d", url, resp.StatusCode)
	}

	doc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return doc, nil
}
