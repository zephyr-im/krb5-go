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
	keytab, err := ctx.OpenKeyTab(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer keytab.Close()
	client, err := ctx.ParseName(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	service, err := ctx.ParseName(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	credential, err := ctx.GetInitialCredentialWithKeyTab(keytab, client, service)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got credential\n")
	log.Printf("\tAuthTime = %v\n", credential.AuthTime())
	log.Printf("\tStartTime = %v\n", credential.StartTime())
	log.Printf("\tEndTime = %v\n", credential.EndTime())
	log.Printf("\tKeyBlock = %v\n", credential.KeyBlock)
	log.Printf("\n")
	log.Printf("raw credential = %v\n", credential)
	log.Printf("\n")
	log.Printf("\n")
	authcon, err := ctx.NewAuthContext()
	if err != nil {
		log.Fatal(err)
	}
	defer authcon.Free()
	request, err := authcon.MakeRequest(credential, 0, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Made authenticator: %#v\n", request)
	key, err := authcon.SessionKey()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Session key: %v\n", key)
}
