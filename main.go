package main

import (
	"encoding/base64"
	"fmt"
)

type person struct {
	First string
}

func main() {
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
	data := []byte("user:pass")
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	fmt.Println(string(dst))
}
