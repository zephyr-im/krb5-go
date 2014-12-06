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
	"log"
	"os"

	"github.com/zephyr-im/krb5-go"
)

func main() {
	ctx, err := krb5.NewContext()
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Free()
	ccache, err := ctx.DefaultCCache()
	if err != nil {
		log.Fatal(err)
	}
	defer ccache.Close()
	log.Printf("Default ccache:\n")
	log.Printf("\tType = %s\n", ccache.Type())
	log.Printf("\tName = %s\n", ccache.Name())
	log.Printf("\tFullName = %s\n", ccache.FullName())
	client, err := ccache.Principal()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("\tPrincipal = %s\n", client)
	service, err := ctx.ParseName(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	credential, err := ctx.GetCredential(ccache, client, service)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got credential\n")
	log.Printf("\tAuthTime = %v\n", credential.AuthTime())
	log.Printf("\tStartTime = %v\n", credential.StartTime())
	log.Printf("\tEndTime = %v\n", credential.EndTime())
	log.Printf("\n")
	log.Printf("raw credential = %v\n", credential)
	log.Printf("\n")
	log.Printf("\n")
	request, err := ctx.MakeRequest(credential, 0, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Made authenticator: %#v\n", request)
}
