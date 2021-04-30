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

func processConnectionToReverseProxy(conn net.Conn, destination string, destPort int, blockKey cipher.Block) {
	addr2 := fmt.Sprintf("%s:%d", destination, destPort)
	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
		log.Panicf("Can't connect to server: %s\n", err)
		return
	}
	Pipe(conn, conn2, blockKey)
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

func encrypt(toEncrypt []byte, blockKey cipher.Block) []byte {
	// ENCRYPT
	nonce := []byte("abcdef123456")
	aesgcm, err := cipher.NewGCM(blockKey)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, toEncrypt, nil)
	// fmt.Println("Writing encrypted text from stdin onto conn:")
	// fmt.Printf("%x\n", ciphertext)
	// conn.Write(b3)
	if err != nil {
		log.Println("Can't connect to server: ", err)
	}
	return ciphertext
}

func decrypt(toDecrypt []byte, blockKey cipher.Block) []byte {
	// DECRYPT
	nonce := []byte("abcdef123456")
	aesgcm, err := cipher.NewGCM(blockKey)
	if err != nil {
		log.Println("Can't connect to server: ", err.Error())
	}
	//log.Println(toDecrypt)
	plaintext, err := aesgcm.Open(nil, nonce, toDecrypt, nil)
	if err != nil {
		log.Println("Decryption Failed:", err.Error())
	}
	// fmt.Println("Writing decrypted text on os.Stdout:")
	// fmt.Printf("%s\n", plaintext)
	// LOL Stdout IS fmt.Print!!
	// conn2.Write(b1)
	return plaintext
}

func startClient(host string, destPort int, blockKey cipher.Block) {

	addr := fmt.Sprintf("%s:%d", host, destPort)
	conn, err := net.Dial("tcp", addr)
	go readClient(conn, blockKey)
	if err != nil {
		log.Println("Can't connect to server: ", err)
		return
	}
	// encrypt and send
	// _, err = io.Copy(conn, os.Stdin)
	stdinchan := chanFromStdin()
	for {
		select {
		case b3 := <-stdinchan:
			if b3 != nil {
				// ENCRYPT
				ciphertext := encrypt(b3, blockKey)
				conn.Write(ciphertext)

				if err != nil {
					log.Println("Can't connect to server: ", err.Error())
				}
			}
		}
	}
}

func readClient(conn net.Conn, blockKey cipher.Block) {
	writer := bufio.NewWriter(os.Stdout)
	for {
		//copy(res, b[:n])

		//decrypt and print
		// _, err := io.Copy(os.Stdout, conn)
		chan1 := chanFromConn(conn)
		for {
			select {
			case b1 := <-chan1:
				if b1 == nil {
					return
				} else {
					// decrypt and write
					// DECRYPT

					plainText := decrypt(b1, blockKey)
					// This is needed as it is Stdout
					//fmt.Printf("%s\n", plainText)
					_, _ = writer.Write(plainText)
					_ = writer.Flush()
				}
			}
		}

	}
}

// chanFromConn creates a channel from a Conn object, and sends everything it
//  Read()s from the socket to the channel.
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
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()
	return c
}

// Pipe creates a full-duplex pipe between the two sockets and transfers data from one to the other.
func Pipe(conn1 net.Conn, conn2 net.Conn, blockKey cipher.Block) {
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
				plainText := decrypt(b1, blockKey)
				conn2.Write(plainText)
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				// encrypt and write
				ciphertext := encrypt(b2, blockKey)
				conn1.Write(ciphertext)
			}

		}

	}
}

func main() {

	// fmt.Println("Starting up PBProxy...")
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
				// TODO: Exit from function! or throw exception?
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

	log.Println("Reverse proxy mode: " + strconv.FormatBool(reverseProxy))
	log.Println("Port to listen to as specified by user: ", listenPort)
	log.Println("Passphrase to be read from file: ", pwdfile)
	log.Println("Destination host as specified by user: ", destination)
	log.Println("Destination port as specified by user: ", destPort)

	log.Println()
	log.Println("===========================")
	log.Println()

	salt := make([]byte, 12)

	pwdKeyBytes, err := ioutil.ReadFile(pwdfile)
	if err != nil {
		// fmt.Println(err)
		log.Panic("Error!! :", err)
	}

	dk := pbkdf2.Key(pwdKeyBytes, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)

	if reverseProxy {

		addr := fmt.Sprintf("%s:%d", "192.168.111.129", listenPort)
		listener, err := net.Listen("tcp", addr)

		// listener = listening for connections between client and 2222
		if err != nil {
			panic(err)
		}

		log.Printf("Listening for connections on %s", listener.Addr().String())

		for {
			conn1, err := listener.Accept()

			if err != nil {
				// fmt.Printf("Error accepting connection from client: %s", err)
				log.Panicf("Error accepting connection from client: %s", err)
			} else {
				go processConnectionToReverseProxy(conn1, destination, destPort, block)
			}
		}

	} else {
		// TODO: we made the client listen on IP and not localhost
		// They'll run the code using localhost naa
		go startClient("192.168.111.129", 2222, block)
	}

}