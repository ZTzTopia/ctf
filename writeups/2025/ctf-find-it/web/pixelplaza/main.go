package main

import (
	"embed"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

//go:embed public/*
var webFS embed.FS

var quotes = []string{
	"Pixels are silent storytellers.",
	"Every bug has a backdoor.",
	"Hacking is not about breaking things, it’s about making things do what you want",
}

type entry struct {
	Name string `json:"name"`
	Msg  string `json:"msg"`
}

type guestbook struct {
	sync.Mutex
	posts []entry
}

var book = &guestbook{posts: make([]entry, 0, 64)}

func apiQuote(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, quotes[rand.Intn(len(quotes))])
}

func apiClock(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, time.Now().Format(time.RFC3339))
}

func apiGuestbook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		book.Lock()
		defer book.Unlock()
		json.NewEncoder(w).Encode(book.posts)
	case http.MethodPost:
		var e entry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		book.Lock()
		book.posts = append(book.posts, e)
		book.Unlock()
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
	}
}

func banner(w http.ResponseWriter, _ *http.Request) {
	http.ServeFile(w, nil, "../docs/banner.png")
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		data, _ := webFS.ReadFile("public/index.html")
		w.Write(data)
		return
	}
	p := "." + r.URL.Path
	if _, err := os.Stat(p); err != nil {
		io.WriteString(w, "Resource not found.")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, filepath.Base(p), fi.ModTime(), f)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	mux := http.NewServeMux()
	mux.HandleFunc("/banner.png", banner)
	mux.HandleFunc("/api/quote", apiQuote)
	mux.HandleFunc("/api/clock", apiClock)
	mux.HandleFunc("/api/guestbook", apiGuestbook)
	fileServer := http.FileServer(http.FS(webFS))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/", staticHandler)
	http.ListenAndServe(":80", mux)
}
