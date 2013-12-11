package warpaddress

import (
	"fmt"
	//"reflect"
	"encoding/hex"
	"math"
	"strings"

	"bytes"
	"log"
	"os/exec"

	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/sha256"
	"github.com/vertis/scrypt"
)

type WarpAddress struct {
	seeds    []string
	output   map[string]string
	Password string
}

func (w *WarpAddress) BitcoinAddress() string {
	return w.output["bitcoinaddress-uncompressed"]
}
func (w *WarpAddress) Seeds() []string {
	return w.seeds
}

func blockXOR(dst, src []byte, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func createScryptSeed(key string, c chan []byte) {
	dk, err := scrypt.Key([]byte(key+"\u0001"), []byte("\u0001"), int(math.Pow(2, 18.0)), 8, 1, 32)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
	}
	c <- dk
}

func createPbkdf2Seed(key string, c chan []byte) {
	dk := pbkdf2.Key([]byte(key+"\u0002"), []byte("\u0002"), 65536, 32, sha256.New)
	c <- dk
}

func createSeeds(key string) [][]byte {
	scryptChannel := make(chan []byte)
	pbkdf2Channel := make(chan []byte)

	go createScryptSeed(key, scryptChannel)
	go createPbkdf2Seed(key, pbkdf2Channel)

	scryptKey := <-scryptChannel
	pbkdf2Key := <-pbkdf2Channel
	finalKey := make([]byte, 32)
	copy(finalKey, scryptKey)
	blockXOR(finalKey, pbkdf2Key, 32)

	return [][]byte{scryptKey, pbkdf2Key, finalKey}
}

func createBitcoinAddress(secret string) map[string]string {
	cmd := exec.Command("bu", "-a", secret)
	//cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	m := make(map[string]string)
	data := strings.Split(out.String(), "\n")
	m["wif-compressed"] = strings.TrimSpace(strings.Split(data[2], ":")[1])
	m["wif-uncompressed"] = strings.TrimSpace(strings.Split(data[3], ":")[1])
	m["hash160-compressed"] = strings.TrimSpace(strings.Split(data[12], ":")[1])
	m["hash160-uncompressed"] = strings.TrimSpace(strings.Split(data[13], ":")[1])
	m["bitcoinaddress-compressed"] = strings.TrimSpace(strings.Split(data[14], ":")[1])
	m["bitcoinaddress-uncompressed"] = strings.TrimSpace(strings.Split(data[15], ":")[1])
	return m
}

func Generate(key string) WarpAddress {
	seeds := createSeeds(key)
	hexSeeds := make([]string, 3)
	for i, s := range seeds {
		hexSeeds[i] = hex.EncodeToString(s)
	}

	result := createBitcoinAddress(hexSeeds[2])
	address := WarpAddress{seeds: hexSeeds, output: result, Password: key}
	return address
}
