package main

import (
	"fmt"
	"os"
	"bufio"
	"net"
	"crypto/sha1"
	"strconv"
	"io/ioutil"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/pbkdf2"
)




func processConnectionToReverseProxy(conn net.Conn, destination string, destPort int, blockKey cipher.Block) {
	addr2 := fmt.Sprintf("%s:%d", destination, destPort)
	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
	  	fmt.Printf("Can't connect to server: %s\n", err)
	  	return
	}
	Pipe(conn, conn2, blockKey)
}


func chanFromStdin() chan []byte {
    c := make(chan []byte)
    go func() {
        for {
			reader := bufio.NewReader(os.Stdin)
			text, err := reader.ReadString('\n')
			if err == nil {
				c <- []byte(text)
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
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	aesgcm, err := cipher.NewGCM(blockKey)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, toEncrypt, nil)
	// fmt.Println("Writing encrypted text from stdin onto conn:")
	// fmt.Printf("%x\n", ciphertext)
	// conn.Write(b3)
	if err != nil {
		fmt.Printf("Connection error: %s\n", err)
	}
	return ciphertext
}

func decrypt(toDecrypt []byte, blockKey cipher.Block) []byte {
	// DECRYPT
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	aesgcm, err := cipher.NewGCM(blockKey)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, toDecrypt, nil)
	if err != nil {
		panic(err.Error())
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
	  	fmt.Printf("Can't connect to server: %s\n", err)
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
					fmt.Printf("Connection error: %s\n", err)
				}
			}
		}
	}
}

func readClient(conn net.Conn, blockKey cipher.Block){

	for{
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
					fmt.Printf("%s\n", plainText)
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
        b := make([]byte, 1024)
        for {
            n, err := conn.Read(b)
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

	fmt.Println("Starting up PBProxy...")

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
				fmt.Println("Error!! :", err)
				// TODO: Exit from function! or throw exception?
			}
			reverseProxy = true
		} else if v == "-p" {
			pwdfile = os.Args[i+1]
		} else if i==1 && os.Args[i] != "-l" && os.Args[i] != "-p" {
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
		fmt.Println("Error!! :", err)
	}

	fmt.Println("Reverse proxy mode: " + strconv.FormatBool(reverseProxy))
	fmt.Println("Port to listen to as specified by user: ", listenPort)
	fmt.Println("Passphrase to be read from file: ", pwdfile)
	fmt.Println("Destination host as specified by user: ", destination)
	fmt.Println("Destination port as specified by user: ", destPort)

	fmt.Println()
	fmt.Println("===========================")
	fmt.Println()

	salt := make([]byte, 12)

	pwdKeyBytes, err := ioutil.ReadFile(pwdfile)
    if err != nil {
		fmt.Println(err)
    }

	dk := pbkdf2.Key(pwdKeyBytes, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)

	if (reverseProxy) {

		addr := fmt.Sprintf("%s:%d", "192.168.111.129", listenPort)
		listener, err := net.Listen("tcp", addr)
	
		// listener = listening for connections between client and 2222
		if err != nil {
			panic(err)
		}
	
		fmt.Printf("Listening for connections on %s", listener.Addr().String())
	
		for {
			conn1, err := listener.Accept()

			if err != nil {
				fmt.Printf("Error accepting connection from client: %s", err)
			} else {
				go processConnectionToReverseProxy(conn1, destination, destPort, block)
			}
		}

	} else {
		// TODO: we made the client listen on IP and not localhost
		// They'll run the code using localhost naa
		startClient("192.168.111.129", 2222, block)
	}

}



