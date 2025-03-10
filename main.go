package main

import (
	"fmt"
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/server"
	"goProxy/core/utils"
	"io"
	"log"
	"os"
	"time"
)

var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500

func main() {

	proxy.Fingerprint = Fingerprint

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	pnc.InitHndl()

	defer pnc.PanicHndl()

	//Disable Error Logging
	log.SetOutput(io.Discard /*logFile*/) // if we ever need to log to a file

	fmt.Println("Starting Proxy ...")

	config.Load()

	fmt.Println("Loaded Config ...")

	// Wait for everything to be initialised

	// Load redis 
	if (proxy.UseRedis) {
		fmt.Println("Loading redis")
		utils.StartRedisPubSub()
	}
	

	fmt.Println("Initialising ...")
	go server.Monitor()
	for !proxy.Initialised {
		time.Sleep(500 * time.Millisecond)
	}

	go server.Serve()

	//Keep server running
	select {}
}
