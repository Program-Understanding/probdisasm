package main

import "flag"

func main() {
	filePath := flag.String("file", "", "path to the binary file")
	flag.Parse()

	if *filePath == "" {
		flag.Usage()
		return
	}

}
