package main

import (
	"crypto"
	"errors"
	"github.com/gorilla/mux"
	"github.com/sec51/twofactor"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

var (
	session        *mgo.Session
	cachedTemplate *template.Template
)

type testUser struct {
	Username   string `bson:"username"`
	Password   string `bson:"password"`
	Token      string `bson:"token"`
	MFAEnabled bool   `bson:"mfaEnabled"`
	Otp        []byte `bson:"otp"`
}

func main() {
	// var err error
	// session, err = mgo.Dial("localhost")
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	r := mux.NewRouter()
	r.HandleFunc("/signup/{username}/{password}", signupHandler)
	r.HandleFunc("/login/{username}/{password}", loginHandler)
	r.HandleFunc("/logout/{username}/{token}", logoutHandler)
	r.HandleFunc("/getProfile/{username}/{token}", getProfileHandler)
	r.HandleFunc("/getQRCode/{username}/{token}", getQRCodeHandler)
	r.HandleFunc("/configureMFA/{username}/{token}/{googleToken}", configureMFAHandler)

	http.ListenAndServe(":8001", r)

	// r.ParseForm()
	// renderHTML := r.Form.Get("html")
	// periodType := r.Form.Get("period_type")
}

func getQRCodeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	token := vars["token"]
	ddd := vars["ddd"]

	if token == "" && ddd == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", "Please send your token to get your qr code")
		return
	}

	user, err := getUserByToken(username, token, session)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	otp, err := twofactor.NewTOTP(user.Username, "GolangTestIssuer", crypto.SHA1, 8)
	if err != nil {
		log.Println(err)
	}

	qrBytes, err := otp.QR()
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	b, err := otp.ToBytes()
	if err != nil {
		log.Println("ToBytes failed")
		w.Header().Set("ErrorText", "ToBytes failed")
		return
	}

	if err := session.DB("mongoDb").C("user").Update(bson.M{"username": user.Username},
		bson.M{"$set": bson.M{"otp": b}}); err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrBytes)))
	if _, err := w.Write(qrBytes); err != nil {
		log.Println("unable to write image.")
	}
	// w.Write(payload)
}

func configureMFAHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	token := vars["token"]
	googleToken := vars["googleToken"]

	if token == "" || googleToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", "Please send your token to get your qr code")
		return
	}

	user, err := getUserByToken(username, token, session)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	otp, err := twofactor.TOTPFromBytes(user.Otp, "GolangTestIssuer")
	if err != nil {
		log.Println("TOTPFromBytes failed.")
		w.Header().Set("ErrorText", "TOTPFromBytes failed")
		return
	}

	// if there is an error, then the authentication failed
	// if it succeeded, then store this information and do not display the QR code ever again.
	err = otp.Validate(googleToken)
	if err != nil {
		log.Println(err)
		w.Header().Set("ErrorText", "Authentication failed")
		return
	}

	if err := session.DB("mongoDb").C("user").Update(bson.M{"username": user.Username},
		bson.M{"$set": bson.M{"mfaEnabled": true}}); err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	// w.Write(payload)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]

	sUser := testUser{
		Username: username,
		Password: password,
	}

	if err := saveUserInMongo(&sUser, session); err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]

	user, err := getUserInMongo(username, password, session)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(404)
		return
	}

	token := user.Username + "_T_" + user.Password
	user.Token = token

	if err := session.DB("mongoDb").C("user").Update(bson.M{"username": user.Username},
		bson.M{"$set": bson.M{"token": user.Token}}); err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Token", token)
	w.WriteHeader(200)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	token := vars["token"]

	user, err := getUserByToken(username, token, session)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	if err := session.DB("mongoDb").C("user").Update(bson.M{"username": user.Username},
		bson.M{"$set": bson.M{"token": ""}}); err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Token", "")
	w.WriteHeader(200)
}

func getProfileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	token := vars["token"]

	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", "Please send your token to get your profile info")
		return
	}

	user, err := getUserByToken(username, token, session)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ErrorText", err.Error())
		w.WriteHeader(404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Username", user.Username)
	w.WriteHeader(200)
}

func saveUserInMongo(user *testUser, session *mgo.Session) error {

	selector := bson.M{"username": user.Username}

	var checkUser testUser
	if err := session.DB("mongoDb").C("user").Find(selector).One(&checkUser); err == nil {
		return errors.New("Please choose a different username")
	}

	if err := session.DB("mongoDb").C("user").Insert(user); err != nil {
		return err
	}
	return nil
}

func getUserInMongo(username, password string, session *mgo.Session) (*testUser, error) {
	selector := bson.M{"username": username, "password": password}

	var user testUser
	if err := session.DB("mongoDb").C("user").Find(selector).One(&user); err != nil {
		return nil, err
	}

	if user.Username == "" {
		return nil, errors.New("User not found or wrong password")
	}

	return &user, nil
}

func getUserByToken(username, token string, session *mgo.Session) (*testUser, error) {
	selector := bson.M{"username": username, "token": token}

	var user testUser
	if err := session.DB("mongoDb").C("user").Find(selector).One(&user); err != nil {
		return nil, err
	}

	if user.Username == "" {
		return nil, errors.New("User not found or wrong token")
	}

	return &user, nil
}
