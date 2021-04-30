package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
)

func processConnectionToReverseProxy(conn net.Conn, destination string, destPort int, pwdKeyBytes []byte) {
	addr2 := fmt.Sprintf("%s:%d", destination, destPort)
	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
		log.Panicf("Can't connect to server: %s\n", err)
		return
	}
	Pipe(conn, conn2, pwdKeyBytes)
}

func chanFromStdin() chan []byte {
	c := make(chan []byte)
	reader := bufio.NewReader(os.Stdin)
	go func() {
		for {
			data := make([]byte, 4096)
			n, err := reader.Read(data)
			//text, err := reader.ReadString('\n')
			if err == nil {
				c <- data[0:n]
			} else {
				c <- nil
				break
			}
		}
	}()
	return c
}

func encrypt(toEncrypt []byte, pwdKeyBytes []byte) []byte {
	salt := []byte("test")
	// salt := pwdKeyBytes
	dk := pbkdf2.Key(pwdKeyBytes, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	nonce := []byte("abcdef123456")
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, toEncrypt, nil)
	if err != nil {
		log.Println("Can't connect to server: ", err)
	}
	return ciphertext
}

func decrypt(toDecrypt []byte, pwdKeyBytes []byte) []byte {
	salt := []byte("test")
	// salt := pwdKeyBytes
	dk := pbkdf2.Key(pwdKeyBytes, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	nonce := []byte("abcdef123456")
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("Can't connect to server: ", err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, toDecrypt, nil)
	if err != nil {
		log.Fatal("Decryption Failed:", err)
	}
	return plaintext
}

func startClient(host string, destPort int, pwdKeyBytes []byte) {

	addr := fmt.Sprintf("%s:%d", host, destPort)
	conn, err := net.Dial("tcp", addr)
	go readClient(conn, pwdKeyBytes)
	if err != nil {
		log.Println("Can't connect to server: ", err)
		return
	}
	stdinchan := chanFromStdin()
	for {
		select {
		case b3 := <-stdinchan:
			if b3 != nil {
				// ENCRYPT
				ciphertext := encrypt(b3, pwdKeyBytes)
				conn.Write(ciphertext)

				if err != nil {
					log.Println("Can't connect to server: ", err.Error())
				}
			}
		}
	}
}

func readClient(conn net.Conn, pwdKeyBytes []byte) {
	writer := bufio.NewWriter(os.Stdout)
	for {
		chan1 := chanFromConn(conn)
		for {
			select {
			case b1 := <-chan1:
				if b1 == nil {
					return
				} else {
					plainText := decrypt(b1, pwdKeyBytes)
					_, _ = writer.Write(plainText)
					_ = writer.Flush()
				}
			}
		}

	}
}


func chanFromConn(conn net.Conn) chan []byte {
	c := make(chan []byte)
	go func() {

		for {
			b := make([]byte, 4096)
			n, err := conn.Read(b)
			if err != nil {
				if err != io.EOF {
					log.Println("Read error:", err)
				}
				break
			}
			if n > 0 {
				c <- b[:n]
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()
	return c
}

func Pipe(conn1 net.Conn, conn2 net.Conn, pwdKeyBytes []byte) {
	chan1 := chanFromConn(conn1)
	chan2 := chanFromConn(conn2)
	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				// decrypt and write
				// DECRYPT
				plainText := decrypt(b1, pwdKeyBytes)
				conn2.Write(plainText)
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				ciphertext := encrypt(b2, pwdKeyBytes)
				conn1.Write(ciphertext)
			}
		}
	}
}

func main() {

	log.Println("Starting up PBProxy...")

	var destination, pwdfile, expression string
	var listenPort, destPort int
	var err interface{}

	destArgs := make([]string, 0)

	var reverseProxy bool
	reverseProxy = false

	for i, v := range os.Args {
		if v == "-l" {
			listenPort, err = strconv.Atoi(os.Args[i+1])
			if err != nil {
				log.Panic("Error!! :", err)
			}
			reverseProxy = true
		} else if v == "-p" {
			pwdfile = os.Args[i+1]
		} else if i == 1 && os.Args[i] != "-l" && os.Args[i] != "-p" {
			expression = os.Args[i]
			destArgs = append(destArgs, expression)
		} else if i > 0 && os.Args[i-1] != "-l" && os.Args[i-1] != "-p" {
			expression = os.Args[i]
			destArgs = append(destArgs, expression)
		}
	}

	destination = destArgs[0]
	destPort, err = strconv.Atoi(destArgs[1])
	if err != nil {
		log.Panic("Error!! :", err)
	}

	log.Println("Passphrase to be read from file name: ", pwdfile)

	// salt := make([]byte, 12)

	pwdKeyBytes, err := ioutil.ReadFile(pwdfile)
	if err != nil {
		log.Panic("Error!! :", err)
	}

	// dk := pbkdf2.Key(pwdKeyBytes, salt, 4096, 32, sha1.New)
	// block, err := aes.NewCipher(dk)

	if reverseProxy {
		
		log.Println("Reverse proxy mode enabled!")
		log.Println("Port to listen to as specified by user: ", listenPort)
		log.Println("Destination host as specified by user: ", destination)
		log.Println("Destination port as specified by user: ", destPort)
		log.Println()
		log.Println("===========================")
		log.Println()
		addr := fmt.Sprintf("%s:%d", destination, listenPort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			panic(err)
		}
		log.Printf("Listening for connections on %s", listener.Addr().String())
		for {
			conn1, err := listener.Accept()
			if err != nil {
				log.Panicf("Error accepting connection from client: %s", err)
			} else {
				go processConnectionToReverseProxy(conn1, destination, destPort, pwdKeyBytes)
			}
		}

	} else {

		log.Println("Client mode enabled!")
		log.Println("Port on the server to connect to: ", destPort)
		log.Println("Destination host as specified by user: ", destination)
		log.Println()
		log.Println("===========================")
		log.Println()
		startClient(destination, destPort, pwdKeyBytes)
	}

}