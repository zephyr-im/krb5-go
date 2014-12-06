// Copyright 2014 The krb5-go authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"regexp"
	"strings"
)

var constRegex = regexp.MustCompile("^#define[ \t]+([A-Z_][A-Z0-9_]+)[ \t]")

var typeName string

func init() {
	flag.StringVar(&typeName, "type", "", "A type to generate with.")
}

type constant struct {
	cConst  string
	goConst string
}

func main() {
	flag.Parse()

	var file *os.File
	switch flag.NArg() {
	case 2:
		file = os.Stdin
	case 3:
		var err error
		file, err = os.Open(flag.Arg(2))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
	default:
		log.Fatal("Usage: PREFIX GOPREFIX [FILE]")
	}
	prefix := flag.Arg(0)
	goPrefix := flag.Arg(1)

	constants := []constant{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		matches := constRegex.FindStringSubmatch(scanner.Text())
		if matches == nil {
			continue
		}
		if len(matches) != 2 {
			panic(matches)
		}
		cConst := matches[1]
		if strings.HasPrefix(cConst, prefix) {
			constants = append(constants, constant{
				cConst, goPrefix + cConst[len(prefix):]})
		}
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "const (\n")
	for _, v := range constants {
		if typeName != "" {
			fmt.Fprintf(&b, "%s %s = C.%s\n", v.goConst, typeName, v.cConst)
		} else {
			fmt.Fprintf(&b, "%s = C.%s\n", v.goConst, v.cConst)
		}
	}
	fmt.Fprintf(&b, ")\n")
	if typeName != "" {
		varName := strings.ToLower(typeName[0:1])
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "func (%s %s) String() string {\n", varName, typeName)
		fmt.Fprintf(&b, "switch %s {\n", varName)
		for _, v := range constants {
			fmt.Fprintf(&b, "case %s:\n", v.goConst)
			fmt.Fprintf(&b, "return %q\n", v.goConst)
		}
		fmt.Fprintf(&b, "default:")
		fmt.Fprintf(&b, "return strconv.Itoa(int(%s))", varName)
		fmt.Fprintf(&b, "}\n")
		fmt.Fprintf(&b, "}\n")
	}

	out, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(out))
}
