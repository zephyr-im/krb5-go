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

package krb5_test

import (
	"reflect"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
)

var defaultRealm = "ATHENA.MIT.EDU"

func stringsEqual(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Got %v, expected %v", actual, expected)
	}
}

func newContextOrFail(t *testing.T) *krb5.Context {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatalf("Error creating context: %v", err)
	}
	return ctx
}

func TestDefaultRealm(t *testing.T) {
	ctx := newContextOrFail(t)
	defer ctx.Free()

	// Set the realm a few times. It should stick.
	realms := []string{
		"EXAMPLE.COM",
		"ATHENA.MIT.EDU",
		"1TS.ORG",
		"DAVIDBEN.NET",
	}
	for _, realm := range realms {
		ctx.SetDefaultRealm(realm)
		r, err := ctx.DefaultRealm()
		if err != nil {
			t.Errorf("ctx.DefaultRealm() failed: %v", err)
		} else if r != realm {
			t.Errorf("ctx.DefaultRealm() = %v; wanted %v", r, realm)
		}
	}
}

func testParseName(t *testing.T, ctx *krb5.Context,
	input string, principal *krb5.Principal) {
	// Parse the principal.
	if p, err := ctx.ParseName(input); err != nil {
		t.Errorf("ctx.ParseName(%v) failed: %v", input, err)
	} else if !reflect.DeepEqual(p, principal) {
		t.Errorf("ctx.ParseName(%v) = %#v; wanted %#v", input, p, principal)
	}
}

func testUnparseName(t *testing.T, ctx *krb5.Context,
	principal *krb5.Principal, output string) {
	if s := principal.String(); s != output {
		t.Errorf("(%#v).String() = %v; wanted %v", principal, s, output)
	}
}

func testParseUnparseNameFull(t *testing.T, ctx *krb5.Context,
	input string, principal *krb5.Principal, output string) {
	testParseName(t, ctx, input, principal)
	testUnparseName(t, ctx, principal, output)
}

func testParseUnparseName(t *testing.T, ctx *krb5.Context,
	input string, principal *krb5.Principal) {
	testParseUnparseNameFull(t, ctx, input, principal, input)
}

func TestParseUnparseName(t *testing.T) {
	ctx := newContextOrFail(t)
	defer ctx.Free()
	ctx.SetDefaultRealm(defaultRealm)

	p := &krb5.Principal{krb5.NT_PRINCIPAL, "ATHENA.MIT.EDU", []string{"davidben"}}
	testParseUnparseName(t, ctx, "davidben@ATHENA.MIT.EDU", p)
	testParseUnparseNameFull(t, ctx, "davidben", p, "davidben@ATHENA.MIT.EDU")

	p.Data[0] = "da\nvidben"
	testParseUnparseName(t, ctx, "da\\nvidben@ATHENA.MIT.EDU", p)

	p.Data[0] = "\\david/ben@"
	testParseUnparseName(t, ctx, "\\\\david\\/ben\\@@ATHENA.MIT.EDU", p)

	p.Data = []string{"davidben", "root"}
	testParseUnparseName(t, ctx, "davidben/root@ATHENA.MIT.EDU", p)

	p.Data = []string{"davidben", "", "", "hi"}
	testParseUnparseName(t, ctx, "davidben///hi@ATHENA.MIT.EDU", p)

	p.Data = []string{"zephyr", "zephyr"}
	testParseUnparseName(t, ctx, "zephyr/zephyr@ATHENA.MIT.EDU", p)

	// Make sure it doesn't crash on empty lists.
	p.Data = []string{}
	testUnparseName(t, ctx, p, "@ATHENA.MIT.EDU")

	p.Data = []string{"davidben"}
	p.Realm = "crazy@realm\nI don't even"
	testParseUnparseName(t, ctx, "davidben@crazy\\@realm\\nI don't even", p)

	// Another edge case.
	p.Realm = ""
	testParseUnparseName(t, ctx, "davidben@", p)

	// Test some bad inputs.
	badInputs := []string{
		"davidben@ATHENA.MIT.EDU\\",
		"foo@bar@baz",
		"davidben@ATHENA/MIT/EDU",
	}
	for _, bad := range badInputs {
		_, err := ctx.ParseName(bad)
		if err == nil {
			t.Errorf("ctx.ParseName(%v) unexpected succeeded", bad)
		}
	}
}

var enctypes = []krb5.EncType{
	krb5.ENCTYPE_DES_CBC_CRC,
	krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96,
	krb5.ENCTYPE_AES256_CTS_HMAC_SHA1_96,
}

func TestMakeRandomKey(t *testing.T) {
	ctx := newContextOrFail(t)
	defer ctx.Free()
	for _, e := range enctypes {
		kb1, err := ctx.MakeRandomKey(e)
		if err != nil {
			t.Errorf("ctx.MakeRandomKey(%v) unexpected failed: %v",
				e, err)
			continue
		}
		if kb1.EncType != e {
			t.Errorf("kb1.EncType = %v; wanted %v", kb1.EncType, e)
		}

		kb2, err := ctx.MakeRandomKey(e)
		if err != nil {
			t.Errorf("ctx.MakeRandomKey(%v) unexpected failed: %v",
				e, err)
			continue
		}
		if kb2.EncType != e {
			t.Errorf("kb2.EncType = %v; wanted %v", kb1.EncType, e)
		}

		if reflect.DeepEqual(kb1, kb2) {
			t.Errorf("Two calls to MakeRandomKey equal: %v, %v",
				kb1, kb2)
		}
	}
}

func TestChecksum(t *testing.T) {
	ctx := newContextOrFail(t)
	defer ctx.Free()
	for _, e := range enctypes {
		kb1, err := ctx.MakeRandomKey(e)
		if err != nil {
			t.Error(err)
			continue
		}
		kb2, err := ctx.MakeRandomKey(e)
		if err != nil {
			t.Error(err)
			continue
		}

		data1 := []byte("Hello, world")
		data2 := []byte("Goodbye, world")

		usage1 := int32(0)
		usage2 := int32(1)

		ck1, err := ctx.MakeChecksum(krb5.SUMTYPE_DEFAULT, kb1, usage1, data1)
		if err != nil {
			t.Errorf("ctx.MakeChecksum(%v, %v, %v, %v) failed: %v",
				krb5.SUMTYPE_DEFAULT, kb1, usage1, data1, err)
			continue
		}

		if result, err := ctx.VerifyChecksum(kb1, usage1, data1, ck1); err != nil {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed: %v",
				kb1, usage1, data1, ck1, err)
		} else if !result {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed",
				kb1, usage1, data1, ck1)
		}

		// Change the usage.
		if result, err := ctx.VerifyChecksum(kb1, usage2, data1, ck1); err != nil {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed: %v",
				kb1, usage1, data1, ck1, err)
		} else if result && e != krb5.ENCTYPE_DES_CBC_CRC {
			// des-cbc-crc ignores the key usage.
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) succeeded",
				kb1, usage1, data1, ck1)
		}

		// Change the data.
		if result, err := ctx.VerifyChecksum(kb1, usage1, data2, ck1); err != nil {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed: %v",
				kb1, usage1, data1, ck1, err)
		} else if result {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) succeeded",
				kb1, usage1, data1, ck1)
		}

		// Change the key.
		if result, err := ctx.VerifyChecksum(kb2, usage1, data1, ck1); err != nil {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed: %v",
				kb1, usage1, data1, ck1, err)
		} else if result {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) succeeded",
				kb1, usage1, data1, ck1)
		}

		// Perturb the checksum slightly.
		ck1.Contents[0] = ck1.Contents[0] + 1
		if result, err := ctx.VerifyChecksum(kb1, usage1, data1, ck1); err != nil {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) failed: %v",
				kb1, usage1, data1, ck1, err)
		} else if result {
			t.Errorf("ctx.VerifyChecksum(%v, %v, %v, %v) succeeded",
				kb1, usage1, data1, ck1)
		}
	}
}

func TestKeyTab(t *testing.T) {
	ctx := newContextOrFail(t)
	defer ctx.Free()

	kt, err := ctx.OpenKeyTab("MEMORY:")
	if err != nil {
		t.Fatalf("ctx.OpenKeyTab failed: %v", err)
	}
	defer kt.Close()

	if ret := kt.Type(); ret != "MEMORY" {
		t.Errorf("kt.Type() = %v; want MEMORY", ret)
	}

	// Generate some quick parameters.
	princ, err := ctx.ParseName("davidben@ATHENA.MIT.EDU")
	if err != nil {
		t.Fatal(err)
	}
	enctype1 := krb5.ENCTYPE_AES256_CTS_HMAC_SHA1_96
	enctype2 := krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96
	kb1, err := ctx.MakeRandomKey(enctype1)
	if err != nil {
		t.Fatal(err)
	}
	kb2, err := ctx.MakeRandomKey(enctype2)
	if err != nil {
		t.Fatal(err)
	}
	kb3, err := ctx.MakeRandomKey(enctype2)
	if err != nil {
		t.Fatal(err)
	}
	entry1 := &krb5.KeyTabEntry{princ, 0, 1, kb1}
	entry2 := &krb5.KeyTabEntry{princ, 0, 1, kb2}
	entry3 := &krb5.KeyTabEntry{princ, 0, 2, kb3}

	// Nothing in there for now.
	if _, err := kt.GetEntry(princ, 0, krb5.EncType(0)); err == nil {
		t.Errorf("kt.GetEntry unexpected succeeded")
	}

	// Insert our entries.
	if err := kt.AddEntry(entry1); err != nil {
		t.Errorf("kt.AddEntry(entry1) failed: %v", err)
	}
	if err := kt.AddEntry(entry2); err != nil {
		t.Errorf("kt.AddEntry(entry2) failed: %v", err)
	}
	if err := kt.AddEntry(entry3); err != nil {
		t.Errorf("kt.AddEntry(entry3) failed: %v", err)
	}

	// Should be able to get them back out.
	if entry, err := kt.GetEntry(princ, 0, krb5.EncType(0)); err != nil {
		t.Errorf("kt.GetEntry failed: %v", err)
	} else if !reflect.DeepEqual(entry, entry3) {
		t.Errorf("kt.GetEntry = %v: want %v", entry, entry3)
	}

	if entry, err := kt.GetEntry(princ, 0, enctype2); err != nil {
		t.Errorf("kt.GetEntry failed: %v", err)
	} else if !reflect.DeepEqual(entry, entry3) {
		t.Errorf("kt.GetEntry = %v: want %v", entry, entry3)
	}

	if entry, err := kt.GetEntry(princ, 0, enctype1); err != nil {
		t.Errorf("kt.GetEntry failed: %v", err)
	} else if !reflect.DeepEqual(entry, entry1) {
		t.Errorf("kt.GetEntry = %v: want %v", entry, entry3)
	}

	if entry, err := kt.GetEntry(princ, 1, enctype2); err != nil {
		t.Errorf("kt.GetEntry failed: %v", err)
	} else if !reflect.DeepEqual(entry, entry2) {
		t.Errorf("kt.GetEntry = %v: want %v", entry, entry2)
	}

	if _, err := kt.GetEntry(princ, 2, enctype1); err == nil {
		t.Errorf("kt.GetEntry unexpected succeeded")
	}

	// Remove them all.
	if err := kt.RemoveEntry(entry1); err != nil {
		t.Errorf("kt.RemoveEntry(entry1) failed: %v", err)
	}
	if err := kt.RemoveEntry(entry2); err != nil {
		t.Errorf("kt.RemoveEntry(entry2) failed: %v", err)
	}
	if err := kt.RemoveEntry(entry3); err != nil {
		t.Errorf("kt.RemoveEntry(entry3) failed: %v", err)
	}

	// Empty now.
	if _, err := kt.GetEntry(princ, 0, krb5.EncType(0)); err == nil {
		t.Errorf("kt.GetEntry unexpected succeeded")
	}
}

func TestMakeReadRequest(t *testing.T) {
	// Make a client credential.
	clientCtx := newContextOrFail(t)
	defer clientCtx.Free()

	clientAuthCon, err := clientCtx.NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	defer clientAuthCon.Free()

	// Make an authenticator.
	cred := krb5test.Credential()
	request, err := clientAuthCon.MakeRequest(cred, 0, nil)
	if err != nil {
		t.Fatalf("clientAuthCon.MakeRequest failed: %v", err)
	}

	// The session key should match.
	if key, err := clientAuthCon.SessionKey(); err != nil {
		t.Fatalf("clientAuthCon.SessionKey() failed: %v", err)
	} else if !reflect.DeepEqual(key, krb5test.SessionKey()) {
		t.Fatalf("clientAuthCon.SessionKey() = %v; want %v", key,
			krb5test.SessionKey())
	}

	// Check it against a server.
	serverCtx := newContextOrFail(t)
	defer serverCtx.Free()

	kt, err := krb5test.MakeServerKeyTab(serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer kt.Close()

	// Consume the authenticator.
	serverAuthCon, err := serverCtx.NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	defer serverAuthCon.Free()
	if err := serverAuthCon.ReadRequest(request, krb5test.Service(), kt); err != nil {
		t.Fatalf("serverAuthCon.ReadRequest failed: %v", err)
	}

	// The server should see the same session key.
	if key, err := serverAuthCon.SessionKey(); err != nil {
		t.Fatalf("serverAuthCon.SessionKey() failed: %v", err)
	} else if !reflect.DeepEqual(key, krb5test.SessionKey()) {
		t.Fatalf("serverAuthCon.SessionKey() = %v; want %v", key,
			krb5test.SessionKey())
	}
}
