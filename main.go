package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"crypto/hmac"
	"crypto/sha512"

	"golang.org/x/crypto/bcrypt"
)

// type person struct {
// 	First string
// }

var key = []byte{}

func main() {
	rand.Seed(time.Now().UnixNano())
	max := 8
	min := 0
	for i := 1; i < 65; i++ {
		x := rand.Intn(max-min+1) + 1
		key = append(key, byte(x))
	}
	// p1 := person{
	// 	First: "Jenny",
	// }

	// p2 := person{
	// 	First: "James",
	// }

	// xp := []person{p1, p2}

	// bs, err := json.Marshal(xp)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// fmt.Println("PRINT JSON", string(bs))

	// xp2 := []person{}

	// err = json.Unmarshal(bs, &xp2)
	// if err != nil {
	// 	log.Panic(err)
	// }

	// fmt.Println("back into a Go data structure", xp2)

	// 	http.HandleFunc("/encode", foo)
	// 	http.HandleFunc("/decode", bar)
	// 	http.ListenAndServe(":8080", nil)
	// }

	// func foo(w http.ResponseWriter, r *http.Request) {
	// 	p1 := person{
	// 		First: "Jenny",
	// 	}

	// 	err := json.NewEncoder(w).Encode(p1)
	// 	if err != nil {
	// 		log.Println("Encoded bad data", err)
	// 	}
	// }

	// func bar(w http.ResponseWriter, r *http.Request) {
	// 	var p2 person
	// 	err := json.NewDecoder(r.Body).Decode(&p2)
	// 	if err != nil {
	// 		log.Println("Decoded bad data", err)
	// 	}

	// 	log.Println("Person:", p2)
	// }

	// 	http.HandleFunc("/encode", foo)
	// 	http.HandleFunc("/decode", bar)
	// 	http.ListenAndServe(":8080", nil)
	// }

	// func foo(w http.ResponseWriter, r *http.Request) {
	// 	p1 := person{
	// 		First: "Jenny",
	// 	}
	// 	p2 := person{
	// 		First: "James",
	// 	}
	// 	peeps := []person{p1, p2}
	// 	err := json.NewEncoder(w).Encode(peeps)
	// 	if err != nil {
	// 		log.Println("Encoded bad data", err)
	// 	}
	// }

	// func bar(w http.ResponseWriter, r *http.Request) {
	// 	p := []person{}
	// 	err := json.NewDecoder(r.Body).Decode(&p)
	// 	if err != nil {
	// 		log.Println("Decoded bad data", err)
	// 	}
	// 	log.Println(p)
	// }

	// data := []byte("user:pass")
	// dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	// base64.StdEncoding.Encode(dst, data)
	// fmt.Println(string(dst))

	password := "34jksnfksdn88934jkf"

	hashedPassword, err := hashPassword(password)
	if err != nil {
		panic(err)
	}

	err = comparePassword(hashedPassword, password)
	if err != nil {
		log.Fatalln("Not logged in!")
	}
	log.Println("Logged in!")
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePassword(hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New512_256, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("error in signMessage while hashing message: %w", err)
	}
	signature := h.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("error in checkSig while hashing message: %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}
