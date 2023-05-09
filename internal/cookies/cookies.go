package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

/* ---------------------------------------------------------------- */
// encode cookie to base64 and match length of cookie
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

// decode cookie from base64
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

/* ---------------------------------------------------------------- */

// signs the cookie with a HMAC signature to ensure integrity
func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	// create a HMAC hash with the secret key
	mac := hmac.New(sha256.New, secretKey)
	// write the cookie name and value to the HMAC hash
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	// save the current hash as the signature to be used in the cookie
	signature := mac.Sum(nil)

	// add the hash signature to the beginning of the cookie value
	cookie.Value = string(signature) + cookie.Value

	// write the cookie to the client by encoding it to base64 using the Write() function
	return Write(w, cookie)
}

// check if the signature in the cookie value matches the recalculated signature
func ReadSigned(r *http.Request, name string, secretKey []byte) (string, error) {
	// read the cookie by decoding it using the Read() function
	signedValue, err := Read(r, name)
	// handle errors
	if err != nil {
		return "", err
	}

	// check if the signed values is at least the same length as a HMAC signature
	if len(signedValue) < sha256.Size {
		return "", ErrInvalidValue
	}

	// split the signature and the cookie value
	signature := signedValue[:sha256.Size]
	cookieValue := signedValue[sha256.Size:]

	// recalculate the HMAC signature using the name and value of the cookie
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(cookieValue))
	// save the current hash as the signature to be used to compare with the signature in the cookie value
	expectedSignature := mac.Sum(nil)

	// check if both signatures match
	if !hmac.Equal(expectedSignature, []byte(signature)) {
		return "", ErrInvalidValue
	}

	// return the original cookie value with no errors
	return cookieValue, nil
}
