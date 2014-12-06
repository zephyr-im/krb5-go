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

// Package krb5test contains test vectors for fake davidben and
// zephyr/zephyr credentials. The relevant keys are randomly
// generated, but a server that believes itself to be Server() with a
// key of ServerKey() and kvno of ServerKeyVersion() should accept
// authenticators made with Credential().
package krb5test

import (
	"encoding/base64"

	"github.com/zephyr-im/krb5-go"
)

var ServerKeyEncType = krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96
var ServerKeyBase64 = "bLf6Aonq1GW3KgYzsE0jNg=="

var SessionKeyEncType = krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96
var SessionKeyBase64 = "VmynPsJVhtihDcIiMRBjOg=="

const AuthTimeRaw = 946702800
const EndTimeRaw = 2145934800

var TicketBase64 = "YYHnMIHkoAMCAQWhEBsOQVRIRU5BLk1JVC5FRFWiG" +
	"zAZoAMCAQKhEjAQGwZ6ZXBoeXIbBnplcGh5cqOBrT" +
	"CBqqADAgERooGiBIGfP1YF6tdilQQW50m+ij1NOWV" +
	"duz1x+xXKVTD+dzcYPTh0J0+Hkmi+gFmv+8coDsIL" +
	"+KLB4o+VuVVanfqlXcSY2LMTU4ZXuziV6TPv8Un6T" +
	"qqxjoH8ZdE18uye2zqHJd4WD2JBr1nWgsACUvHeZH" +
	"99QX2EOAu33cpif9pgvZ6v2A+d3xWsqGd1DvzLpBP" +
	"Rite3uMkgalFWsT/FOlX/IbqU"

var Realm = "ATHENA.MIT.EDU"

func mustDecodeString(in string) []byte {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

func ServerKey() *krb5.KeyBlock {
	return &krb5.KeyBlock{
		ServerKeyEncType, mustDecodeString(ServerKeyBase64)}
}

func ServerKeyVersion() uint {
	return 1
}

func MakeServerKeyTab(ctx *krb5.Context) (*krb5.KeyTab, error) {
	kt, err := ctx.OpenKeyTab("MEMORY:")
	if err != nil {
		return nil, err
	}
	kte := &krb5.KeyTabEntry{
		Service(), 0, ServerKeyVersion(), ServerKey()}
	if err := kt.AddEntry(kte); err != nil {
		return nil, err
	}
	return kt, nil
}

func SessionKey() *krb5.KeyBlock {
	return &krb5.KeyBlock{
		SessionKeyEncType, mustDecodeString(SessionKeyBase64)}
}

func Ticket() []byte {
	return mustDecodeString(TicketBase64)

}

func Client() *krb5.Principal {
	return &krb5.Principal{
		krb5.NT_PRINCIPAL, Realm, []string{"davidben"}}
}

func Service() *krb5.Principal {
	return &krb5.Principal{
		krb5.NT_SRV_INST, Realm, []string{"zephyr", "zephyr"}}
}

func Credential() *krb5.Credential {
	return &krb5.Credential{
		Client(), Service(), SessionKey(), AuthTimeRaw, 0,
		EndTimeRaw, 0, false, 0, nil, Ticket(), nil, nil}
}
