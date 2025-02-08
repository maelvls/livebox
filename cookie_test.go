package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCookie(t *testing.T) {
	testCases := []struct {
		name           string
		cookieHeader   string
		expectedCookie *http.Cookie
		expectedError  bool
	}{
		{
			name:         "valid cookie",
			cookieHeader: "e87d7dbd/sessid=Tg1OUU6QJQhKhY9Q1UpMkiR+; path=/; SameSite=Strict; HttpOnly",
			expectedCookie: &http.Cookie{
				Name:     "e87d7dbd/sessid",
				Value:    "Tg1OUU6QJQhKhY9Q1UpMkiR+",
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				HttpOnly: true,
			},
			expectedError: false,
		},
		{
			name:           "missing sessid",
			cookieHeader:   "path=/; SameSite=Strict; HttpOnly",
			expectedCookie: nil,
			expectedError:  true,
		},
		{
			name:           "empty cookie",
			cookieHeader:   "",
			expectedCookie: nil,
			expectedError:  true,
		},
		{
			name:         "cookie with extra attributes",
			cookieHeader: "e87d7dbd/sessid=Tg1OUU6QJQhKhY9Q1UpMkiR+; path=/; domain=example.com; Secure; HttpOnly",
			expectedCookie: &http.Cookie{
				Name:     "e87d7dbd/sessid",
				Value:    "Tg1OUU6QJQhKhY9Q1UpMkiR+",
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				HttpOnly: true,
			},
			expectedError: false,
		},
		{
			name:         "cookie with spaces",
			cookieHeader: "  e87d7dbd/sessid=Tg1OUU6QJQhKhY9Q1UpMkiR+  ;  path=/  ;  SameSite=Strict  ;  HttpOnly  ",
			expectedCookie: &http.Cookie{
				Name:     "e87d7dbd/sessid",
				Value:    "Tg1OUU6QJQhKhY9Q1UpMkiR+",
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				HttpOnly: true,
			},
			expectedError: false,
		},
		{
			name:           "invalid cookie format",
			cookieHeader:   "e87d7dbd=Tg1OUU6QJQhKhY9Q1UpMkiR+; path=/; SameSite=Strict; HttpOnly",
			expectedCookie: nil,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cookie, err := parseCookie(tc.cookieHeader)

			if tc.expectedError {
				assert.Error(t, err, "Expected error")
			} else {
				assert.NoError(t, err, "Unexpected error")
				assert.Equal(t, tc.expectedCookie.Name, cookie.Name, "Cookie name mismatch")
				assert.Equal(t, tc.expectedCookie.Value, cookie.Value, "Cookie value mismatch")
				assert.Equal(t, tc.expectedCookie.Path, cookie.Path, "Cookie path mismatch")
				assert.Equal(t, tc.expectedCookie.SameSite, cookie.SameSite, "Cookie SameSite mismatch")
				assert.Equal(t, tc.expectedCookie.HttpOnly, cookie.HttpOnly, "Cookie HttpOnly mismatch")
			}
		})
	}
}
