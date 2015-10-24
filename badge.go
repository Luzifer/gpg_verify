package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
	"text/template"
)

type verificationStatus uint

const (
	verificationStatusOK verificationStatus = iota
	verificationStatusFailed
	verificationStatusError
)

func renderBadge(res http.ResponseWriter, status verificationStatus, filename string, checkedAt time.Time, reason, key string) error {
	log.Printf("Rendering: %d", status)
	var color, result string

	switch status {
	case verificationStatusOK:
		color = "#4c1"
		result = fmt.Sprintf("Success, signed by %s", key)
	case verificationStatusFailed:
		color = "#e05d44"
		result = "Invalid"
	case verificationStatusError:
		color = "#e05d44"
		result = "Errored"
	}

	vars := struct {
		Filename string
		Result   string
		Date     string
		Color    string
	}{
		Filename: filename,
		Result:   result,
		Date:     checkedAt.Format("2006-01-02 15:04"),
		Color:    color,
	}

	if reason != "" {
		res.Header().Set("X-Reason", reason)
	}

	badgeSrc, _ := Asset("assets/badge.svg")
	tpl, err := template.New("badge").Parse(string(badgeSrc))
	if err != nil {
		return err
	}
	if err := tpl.Execute(res, vars); err != nil {
		return err
	}

	return nil
}
