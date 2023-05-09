package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/LeePanti/final_project/internal/cookies"
)

func main() {
	// router
	mux := http.NewServeMux()

	// routes
	mux.HandleFunc("/set", setCookie)
	mux.HandleFunc("/get", getCookie)
	mux.HandleFunc("/setcharacters", setCharacters)
	mux.HandleFunc("/getcharacters", getCharacters)
	mux.HandleFunc("/setprotected", setProtected)
	mux.HandleFunc("/getprotected", getProtected)
	mux.HandleFunc("/setencrypted", setEncrypted)
	mux.HandleFunc("/getencrypted", getEncrypted)
	mux.HandleFunc("/settype", setType)
	mux.HandleFunc("/gettype", getType)

	// secret key for tamper proofing
	var err error
	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
	if err != nil {
		log.Fatal(err)
	}

	// register the Type that we want to encode
	gob.Register(&User{})

	// server
	log.Println("starting server on port 9000...")
	err = http.ListenAndServe(":9000", mux)
	if err != nil {
		log.Fatal(err)
	}
}

/* ----------------------------------------------------------------------------- */
// Basic example of using a cookie in a web application

// setting the cookie
func setCookie(w http.ResponseWriter, r *http.Request) {
	// create a cookie with all required attributes
	cookie := http.Cookie{
		Name:     "basicCookie",
		Value:    "value of the basic cookie",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// set the cookie so that it is sent to the client.
	http.SetCookie(w, &cookie)

	// write out a response to the client
	w.Write([]byte("Basic cookie has been set"))
}

// getting the cookie
func getCookie(w http.ResponseWriter, r *http.Request) {
	// get the cookie from the request and handle any errors
	cookie, err := r.Cookie("basicCookie")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "No cookie found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	// write the cookie values to the client
	w.Write([]byte(cookie.Value))
}

/* ------------------------------------------------------------------------------- */

// encoding special characters in the cookie value and checking cookie length

// setting the cookie
func setCharacters(w http.ResponseWriter, r *http.Request) {
	// create the cookie
	cookie := http.Cookie{
		Name:  "specialCharactersCookie",
		Value: "你好, 很高兴见到你",
	}

	// write the cookie using the internal/cookies package function Write()
	err := cookies.Write(w, cookie)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// write out a response to the client
	w.Write([]byte("Special characters cookie has been set"))
}

// getting the cookie value
func getCharacters(w http.ResponseWriter, r *http.Request) {
	// read the cookie using the internal/cookies package function Read()
	cookieValue, err := cookies.Read(r, "specialCharactersCookie")

	// handle the errors
	if err != nil {
		handleErrors(w, err)
		return
	}

	// write the cookie value to the client
	w.Write([]byte(cookieValue))
}

/* ----------------------------------------------------------------------------- */

// setting up a tamper proof cookie with a HMAC signature infront of the cookie value

// secret key for the HMAC signature
var secretKey []byte

// setting the cookie
func setProtected(w http.ResponseWriter, r *http.Request) {
	// create the cookie
	cookie := http.Cookie{
		Name:  "signedCookie",
		Value: "this is the value in the tampered proof cookie",
	}

	// set the cookie using the internal/cookies package function WriteSigned()
	err := cookies.WriteSigned(w, cookie, secretKey) // global secret key variable
	// handle the errors
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// write out a response to the client
	w.Write([]byte("tamper proof cookie has been set"))

}

// getting the cookie
func getProtected(w http.ResponseWriter, r *http.Request) {
	// read the cookie using the internal/cookies package function ReadSigned()
	cookieValue, err := cookies.ReadSigned(r, "signedCookie", secretKey)
	// handle the errors
	if err != nil {
		handleErrors(w, err)
		return
	}

	// write the cookie value to the client
	w.Write([]byte(cookieValue))
}

/* ----------------------------------------------------------------------------- */

// setting up an ecrypted cookie with AES-GCM encryption

// setting the cookie
func setEncrypted(w http.ResponseWriter, r *http.Request) {
	// create the cookie
	cookie := http.Cookie{
		Name:  "encryptedCookie",
		Value: "This is the encrypted cookie value.",
	}

	// set the cookie using the internal/cookies package function WriteEncrypted()
	err := cookies.WriteEncrypted(w, cookie, secretKey)
	// handle the errors
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// write out a response to the client
	w.Write([]byte("Encrypted cookie has been set"))
}

// getting the cookie
func getEncrypted(w http.ResponseWriter, r *http.Request) {
	// decrypt the cookie using the internal/cookies package function ReadEncrypted()
	cookieValue, err := cookies.ReadEncrypted(r, "encryptedCookie", secretKey)
	if err != nil {
		handleErrors(w, err)
		return
	}

	// write the cookie value to the client
	w.Write([]byte(cookieValue))
}

/* ----------------------------------------------------------------------------- */

// storing custom data types in cookies using the GOB encoding package

// create the data type struct
type User struct {
	Name string
	Age  int
}

// setting the cookie
func setType(w http.ResponseWriter, r *http.Request) {
	// create a user struct
	user := User{
		Name: "Lee",
		Age:  20,
	}

	// buffer to hold the gob encoded data
	var buf bytes.Buffer

	// Gob-encode the user struct
	err := gob.NewEncoder(&buf).Encode(&user)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// create the cookie
	cookie := http.Cookie{
		Name:  "customTypeCookie",
		Value: buf.String(),
	}

	// encrypt and set the cookie
	err = cookies.WriteEncrypted(w, cookie, secretKey)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// write out a response to the client
	w.Write([]byte("custom type cookie set"))
}

// getting the cookie
func getType(w http.ResponseWriter, r *http.Request) {
	// decrypt the cookie using the internal/cookies ReadEncrypted() function
	gobCookieValue, err := cookies.ReadEncrypted(r, "customTypeCookie", secretKey)
	if err != nil {
		handleErrors(w, err)
	}

	// create a user struct to store the cookie value
	var user User

	// create a string.reader to read the gob encoded data (similar to the buffer)
	reader := strings.NewReader(gobCookieValue)

	// decode into the user struct
	err = gob.NewDecoder(reader).Decode(&user)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// print the user to the client
	fmt.Fprintf(w, "Name: %s\n", user.Name)
	fmt.Fprintf(w, "Value: %d\n", user.Age)
}

// handle the possible errors
func handleErrors(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, http.ErrNoCookie):
		http.Error(w, "cookie not found", http.StatusBadRequest)
	case errors.Is(err, cookies.ErrInvalidValue):
		http.Error(w, "invalid cookie value", http.StatusBadRequest)
	default:
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}
