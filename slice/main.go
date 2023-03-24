package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	getSig = flag.Bool("sig", false, "whether to get signature")
	d      = flag.String("data", "", "data to parse")
)

func main() {
	flag.Parse()
	data := *d
	if strings.HasPrefix(data, "0x") {
		data = data[2:]
	}
	if len(data) >= 8 && len(data)%64 != 0 {
		funcSig := data[0:8]
		data = data[8:]
		fmt.Println("\nfunction signature:")
		fmt.Printf("\n" + funcSig)
		if *getSig {
			funcSigText := getSignature(funcSig)
			fmt.Printf(" [%s]\n", funcSigText)
		} else {
			fmt.Println()
		}
	}
	print(data)
}

func print(data string) {
	fmt.Println("\ndata:")
	fmt.Println("")
	for i := 0; i < len(data); i += 64 {
		fmt.Println(data[i : i+64])
	}
	fmt.Println("")
}

type GetSigRes struct {
	Results []SigResult `json:"results"`
}

type SigResult struct {
	TextSignature string `json:"text_signature"`
}

func getSignature(b string) string {
	url := fmt.Sprintf("https://www.4byte.directory/api/v1/signatures/?hex_signature=%s", b)
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	res := GetSigRes{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		panic(err)
	}
	if len(res.Results) == 0 {
		return "not found"
	}
	ret := []string{}
	for _, r := range res.Results {
		ret = append(ret, r.TextSignature)
	}
	return strings.Join(ret, ", ")
}
