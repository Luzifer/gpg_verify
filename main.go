package main

//go:generate go-bindata -o assets.go assets/

import (
	"net/http"

	"github.com/Luzifer/rconfig"
	"github.com/gorilla/mux"
)

var (
	cfg = struct {
		Listen  string `flag:"listen" default:":3000" description:"Adress / port to bind to"`
		GPGPath string `flag:"gpgpath" default:"/usr/bin/gpg" description:"GPG binary to use"`
	}{}
)

func init() {
	rconfig.Parse(&cfg)
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/verify", verifyOnlineDocument)

	http.ListenAndServe(cfg.Listen, r)
}
