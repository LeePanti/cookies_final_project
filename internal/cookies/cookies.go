package cookies

import (
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

// encode and match length of cookie
func Write(w http.ResponseWriter, cookie http.Cookie) error {
	// encode cookie value to base64 for compatibility
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	// check cookie length
	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}

	// write the cookie to the response
	http.SetCookie(w, &cookie)

	// return no error
	return nil
}

func Read(r *http.Request, name string) (string, error) {
	// read cookie from request and handle errors
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	// decode cookie value from base64 and handle errors
	cookieValue, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	// return the cookie value and no errors
	return string(cookieValue), nil
}
