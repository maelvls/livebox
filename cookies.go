package main

import (
	"fmt"
	"net/http"
	"strings"
)

// We can't rely on http.ParseCookie because the cookie contains a `/`, which
// is not a valid character for a cookie name. It looks like this:
//
//	e87d7dbd/sessid=Tg1OUU6QJQhKhY9Q1UpMkiR+; path=/; SameSite=Strict; HttpOnly
//	        ^ not compliant with RFC 6265
//
// So we'll parse it manually.
func parseCookie(setCookieHeader string) (*http.Cookie, error) {
	parts := strings.Split(setCookieHeader, ";")
	var sessidKey, sessidValue string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "/sessid=") {
			parts := strings.SplitN(part, "=", 2)
			sessidKey = parts[0]
			sessidValue = parts[1]
			break
		}
	}

	if sessidValue == "" {
		return nil, fmt.Errorf("sessid cookie not found in Set-Cookie header")
	}

	return &http.Cookie{
		Name:     sessidKey,
		Value:    sessidValue,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	}, nil
}
