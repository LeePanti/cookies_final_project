package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/LeePanti/final_project/internal/cookies"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/set", setCookie)
	mux.HandleFunc("/get", getCookie)

	log.Println("starting server on port 9000...")
	err := http.ListenAndServe(":9000", mux)
	if err != nil {
		log.Fatal(err)
	}
}

/* ---------------------------------------------------------------- */
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

/* ---------------------------------------------------------------- */

// encoding special characters in the cookie value and checking cookie length

// setting the cookie
func setcharacters(w http.ResponseWriter, r *http.Request) {
	// create the cookie
	cookie := http.Cookie{
		Name:  "specialCharactersCookie",
		Value: "你好, 很高兴见到你",
	}

	// write the cookie using the encoding package function Write()
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
func getcharacters(w http.ResponseWriter, r *http.Request) {

}
