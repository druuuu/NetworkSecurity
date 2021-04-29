package main

import (
	"fmt" //for loggin errors
	// "strings"
	"os"
	"io"
	"net"
	// "time"
	"strconv"
)



// func startServer(host string, listenPort int) {
	
// 	// host = "localhost"

// 	addr := fmt.Sprintf("%s:%d", host, listenPort)
// 	listener, err := net.Listen("tcp", addr)
  
// 	if err != nil {
// 		panic(err)
// 	}
  
// 	fmt.Printf("Listening for connections on %s", listener.Addr().String())
  
// 	for {

// 	  	conn, err := listener.Accept()
// 	  	if err != nil {
// 			fmt.Printf("Error accepting connection from client: %s", err)
// 	  	}
// 		//    else {
// 		// 	go processClient(conn)
// 	  	// }
	
// 	}

// }

func processConnectionToReverseProxy(conn net.Conn, destination string, destPort int) {
	
	addr2 := fmt.Sprintf("%s:%d", destination, destPort)

	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
	  	fmt.Printf("Can't connect to server: %s\n", err)
	  	return
	}

	Pipe(conn, conn2)

}

// func processClient(conn net.Conn) {

// 	_, err := io.Copy(os.Stdout, conn)
// 	if err != nil {
// 	  	fmt.Println(err)
// 	}
// 	conn.Close()
// }
  
func startClient(host string, destPort int) {

	addr := fmt.Sprintf("%s:%d", host, destPort)

	conn, err := net.Dial("tcp", addr)


	go readClient(conn)
	if err != nil {
	  	fmt.Printf("Can't connect to server: %s\n", err)
	  	return
	}
	_, err = io.Copy(conn, os.Stdin)
	if err != nil {
	  	fmt.Printf("Connection error: %s\n", err)
	}

}

func readClient(conn net.Conn){

	for{
		//copy(res, b[:n])
		_, err := io.Copy(os.Stdout, conn)
		if err != nil {
			  	fmt.Println(err)
			}
		}


	// c := make(chan []byte)

    // go func() {
    //     b := make([]byte, 1024)

    //     for {
    //         n, err := conn.Read(b)
    //         if n > 0 {
    //             res := make([]byte, n)
    //             // Copy the buffer so it doesn't get changed while read by the recipient.
    //             copy(res, b[:n])
	// 				_, err := io.Copy(os.Stdout, conn)
	// if err != nil {
	//   	fmt.Println(err)
	// }
    //             c <- res
    //         }
    //         if err != nil {
    //             c <- nil
    //             break
    //         }
    //     }
    // }()

    // return c
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
func Pipe(conn1 net.Conn, conn2 net.Conn) {
    chan1 := chanFromConn(conn1)
    chan2 := chanFromConn(conn2)

    for {
        select {
        case b1 := <-chan1:
            if b1 == nil {
                return
            } else {
                conn2.Write(b1)
            }
        case b2 := <-chan2:
            if b2 == nil {
                return
            } else {
                conn1.Write(b2)
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

	// if (reverseProxy) {
	// 	startServer("localhost", listenPort)
	// } else {
	// 	startClient("localhost", destPort)
	// }

	if (reverseProxy) {
		// listenPort = 2222
		addr := fmt.Sprintf("%s:%d", "192.168.111.129", listenPort)
		listener, err := net.Listen("tcp", addr)
	
		// listener = listening for connections between client and 2222

		if err != nil {
			panic(err)
		}
	
		fmt.Printf("Listening for connections on %s", listener.Addr().String())
	
		for {

			conn1, err := listener.Accept()
			// received conn between client and 2222
			// call this conn1

			// now we gotta create (Dial?) a connection to 22 
			// call this connection conn2
			
			// Then pipe conn1, conn2

			// Pipe()


			if err != nil {
				fmt.Printf("Error accepting connection from client: %s", err)
			} else {
				// go processClient(conn)
				go processConnectionToReverseProxy(conn1, destination, destPort)
			}
		}

	} else {
		// conn, err := net.Dial("tcp", "192.168.111.129:2222")
		
		// Dial a connection to "192.168.111.129" : port "2222"
		// 

		startClient("192.168.111.129", 2222)
	}


	


}



