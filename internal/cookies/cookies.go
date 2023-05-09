package cookies

import (
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
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
