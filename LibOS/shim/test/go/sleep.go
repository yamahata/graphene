package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("sleeping")
	time.Sleep(100 * time.Millisecond)
	fmt.Println("done")
}
