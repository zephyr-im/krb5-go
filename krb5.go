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

// Package krb5 is a set of Go bindings to the MIT Kerberos library.
package krb5

// #cgo LDFLAGS: -lkrb5 -lk5crypto -lcom_err
// #include <krb5.h>
// #include <limits.h>
// #include <string.h>
//
// static krb5_error_code make_checksum(krb5_context context,
//                                      krb5_cksumtype cksumtype,
//                                      krb5_keyblock key,
//                                      krb5_keyusage usage,
//                                      krb5_data input,
//                                      krb5_checksum *cksum) {
//   return krb5_c_make_checksum(context, cksumtype, &key, usage, &input, cksum);
// }
//
// static krb5_error_code verify_checksum(krb5_context context,
//                                        krb5_keyblock key,
//                                        krb5_keyusage usage,
//                                        krb5_data data,
//                                        krb5_checksum cksum,
//                                        krb5_boolean *valid) {
//   return krb5_c_verify_checksum(context, &key, usage, &data, &cksum, valid);
// }
//
// static krb5_error_code kt_add_entry(krb5_context context, krb5_keytab id,
//                                     krb5_keytab_entry entry) {
//   return krb5_kt_add_entry(context, id, &entry);
// }
//
// static krb5_error_code kt_remove_entry(krb5_context context, krb5_keytab id,
//                                        krb5_keytab_entry entry) {
//   return krb5_kt_remove_entry(context, id, &entry);
// }
//
// static krb5_error_code mk_req_extended(krb5_context context,
//                                        krb5_auth_context *auth_context,
//                                        krb5_flags ap_req_options,
//                                        krb5_data *in_data,
//                                        krb5_creds in_creds,
//                                        krb5_data *outbuf) {
//   return krb5_mk_req_extended(context, auth_context, ap_req_options, in_data, &in_creds, outbuf);
// }
import "C"

import (
	"math"
	"time"
	"unsafe"
)

func bytesToKrb5Data(b []byte) C.krb5_data {
	if len(b) == 0 {
		return C.krb5_data{length: 0, data: nil}
	}
	if len(b) > C.UINT_MAX {
		panic("Data too large.")
	}
	return C.krb5_data{length: C.uint(len(b)), data: (*C.char)(C.CBytes(b))}
}

func bytesToKrb5DataAlias(b []byte) C.krb5_data {
	if len(b) > C.UINT_MAX {
		panic("Data too large.")
	}
	return C.krb5_data{length: C.uint(len(b)), data: unsafeCharPtr(b)}
}

func stringToKrb5Data(s string) C.krb5_data {
	return bytesToKrb5Data([]byte(s))
}

// Frees a krb5_data allocated by bytesToKrb5Data or stringToKrb5Data.
func freeKrb5Data(d *C.krb5_data) {
	C.free(unsafe.Pointer(d.data))
	d.data = nil
}

func krb5DataToString(d *C.krb5_data) string {
	if d.data == nil {
		if d.length != 0 {
			panic(d.length)
		}
		return ""
	}
	return C.GoStringN(d.data, C.int(d.length))
}

func krb5DataToBytes(d *C.krb5_data) []byte {
	if d.length == 0 {
		return nil
	}
	if d.length > C.INT_MAX {
		panic("Length too large.")
	}
	return C.GoBytes(unsafe.Pointer(d.data), C.int(d.length))
}

func unsafeOctetPtr(b []byte) *C.krb5_octet {
	if len(b) == 0 {
		return nil
	}
	return (*C.krb5_octet)(unsafe.Pointer(&b[0]))
}

func unsafeCharPtr(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

// Freed with C.free.
func cOctetPtr(b []byte) *C.krb5_octet {
	if len(b) == 0 {
		return nil
	}
	return (*C.krb5_octet)(C.CBytes(b))
}

// Error-handling.

// An Error is a krb5 library error. It may internally have an
// associated context.
type Error struct {
	context *Context
	code    int32
}

// ErrorCode returns the C error code for this library.
func (err *Error) ErrorCode() int32 {
	return err.code
}

// Error implements the error interface. It returns the error from
// obtained from krb5.
func (err *Error) Error() string {
	var ctx C.krb5_context
	if err.context != nil {
		ctx = err.context.ctx
	}
	message := C.krb5_get_error_message(ctx, C.krb5_error_code(err.code))
	defer C.krb5_free_error_message(ctx, message)
	return C.GoString(message)
}

func contextlessError(code C.krb5_error_code) *Error {
	return &Error{&Context{C.krb5_context(nil)}, int32(code)}
}

// Context creation.

// A Context wraps a krb5_context and is passed in to most functions.
type Context struct {
	ctx C.krb5_context
}

// NewContext creates a new Context with default parameters. It must
// be released with Free.
func NewContext() (*Context, error) {
	var ctx C.krb5_context
	if code := C.krb5_init_context(&ctx); code != 0 {
		return nil, contextlessError(code)
	}
	return &Context{ctx}, nil
}

// Free releases resources associated with a context.
func (ctx *Context) Free() {
	C.krb5_free_context(ctx.ctx)
	ctx.ctx = C.krb5_context(nil)
}

func (ctx *Context) makeError(code C.krb5_error_code) *Error {
	return &Error{ctx, int32(code)}
}

// ErrorMessage returns the error message for a given error code.
func (ctx *Context) ErrorMessage(code int32) string {
	return ctx.makeError(C.krb5_error_code(code)).Error()
}

// Context properties.

// DefaultRealm returns the default realm associated with a context.
func (ctx *Context) DefaultRealm() (string, error) {
	var realmC *C.char
	if code := C.krb5_get_default_realm(ctx.ctx, &realmC); code != 0 {
		return "", ctx.makeError(code)
	}
	defer C.krb5_free_default_realm(ctx.ctx, realmC)
	return C.GoString(realmC), nil
}

// SetDefaultRealm overrides the default realm.
func (ctx *Context) SetDefaultRealm(realm string) {
	realmC := C.CString(realm)
	defer C.free(unsafe.Pointer(realmC))
	if code := C.krb5_set_default_realm(ctx.ctx, realmC); code != 0 {
		// krb5_set_default_realm should never fail for a
		// legitimate context.
		panic(ctx.makeError(code))
	}
}

// ResetDefaultRealm resets the default realm to the system default one.
func (ctx *Context) ResetDefaultRealm() {
	if code := C.krb5_set_default_realm(ctx.ctx, nil); code != 0 {
		// krb5_set_default_realm should never fail for a
		// legitimate context.
		panic(ctx.makeError(code))
	}
}

// Principals

// A Principal is a value type representing a Kerberos principal.
type Principal struct {
	Type  NameType
	Realm string
	Data  []string
}

func principalFromC(princ C.krb5_principal) *Principal {
	dataCast := (*[1 << 30]C.krb5_data)(unsafe.Pointer(princ.data))[:princ.length]
	data := make([]string, 0, princ.length)
	for i := 0; i < int(princ.length); i++ {
		data = append(data, krb5DataToString(&dataCast[i]))
	}
	return &Principal{
		Type:  NameType(princ._type),
		Realm: krb5DataToString(&princ.realm),
		Data:  data}
}

// toC converts p to a C structure. It must be freed with
// freeKrb5PrincipalData.
func (p *Principal) toC() C.krb5_principal_data {
	data := p.Data
	// Don't crash on empty strings.
	if len(p.Data) == 0 {
		data = []string{""}
	}
	if len(p.Data) > math.MaxUint32 {
		panic("Principal too large.")
	}
	dataC := C.malloc(C.size_t(C.sizeof_krb5_data * len(data)))
	dataCast := (*[1 << 30]C.krb5_data)(dataC)
	for i, v := range data {
		dataCast[i] = stringToKrb5Data(v)
	}
	return C.krb5_principal_data{
		realm:  stringToKrb5Data(p.Realm),
		data:   (*C.krb5_data)(dataC),
		length: C.krb5_int32(len(data)),
		_type:  C.krb5_int32(p.Type)}
}

func freeKrb5PrincipalData(p *C.krb5_principal_data) {
	freeKrb5Data(&p.realm)
	dataCast := (*[1 << 30]C.krb5_data)(unsafe.Pointer(p.data))[:p.length]
	for i := 0; i < int(p.length); i++ {
		freeKrb5Data(&dataCast[i])
	}
}

// toCPtr converts p to a krb5-owned C.krb5_principal. It must be freed with
// C.krb5_free_principal.
func (p *Principal) toCPtr(ctx *Context) C.krb5_principal {
	templ := p.toC()
	defer freeKrb5PrincipalData(&templ)
	var ret C.krb5_principal
	if code := C.krb5_copy_principal(ctx.ctx, &templ, &ret); code != 0 {
		panic(ctx.makeError(code))
	}
	return ret
}

// String returns the serialized form of a principal.
func (p *Principal) String() string {
	var name *C.char
	principal := p.toC()
	defer freeKrb5PrincipalData(&principal)
	if code := C.krb5_unparse_name(C.krb5_context(nil), &principal, &name); code != 0 {
		panic(contextlessError(code))
	}
	defer C.krb5_free_unparsed_name(C.krb5_context(nil), name)
	return C.GoString(name)
}

// ParseName parses a string into a Principal, taking into account the
// context's default realm.
func (ctx *Context) ParseName(name string) (*Principal, error) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	princ := C.krb5_principal(nil)
	if code := C.krb5_parse_name(ctx.ctx, nameC, &princ); code != 0 {
		return nil, ctx.makeError(code)
	}
	defer C.krb5_free_principal(ctx.ctx, princ)
	return principalFromC(princ), nil
}

// Basic crypto.

// A Checksum is a value type containing a checksum generated from a
// Kerberos key.
type Checksum struct {
	SumType  SumType
	Contents []byte
}

func checksumFromC(cksum *C.krb5_checksum) *Checksum {
	return &Checksum{
		SumType:  SumType(cksum.checksum_type),
		Contents: C.GoBytes(unsafe.Pointer(cksum.contents), C.int(cksum.length))}
}

func (c *Checksum) toC() C.krb5_checksum {
	return C.krb5_checksum{
		checksum_type: C.krb5_cksumtype(c.SumType),
		length:        C.uint(len(c.Contents)),
		contents:      unsafeOctetPtr(c.Contents)}
}

// A KeyBlock is a value type containing a Kerberos key.
// TODO(davidben): Wrap krb5_key if the performance is ever relevant.
type KeyBlock struct {
	EncType  EncType
	Contents []byte
}

func keyBlockFromC(k *C.krb5_keyblock) *KeyBlock {
	return &KeyBlock{
		EncType:  EncType(k.enctype),
		Contents: C.GoBytes(unsafe.Pointer(k.contents), C.int(k.length))}
}

func (k *KeyBlock) toC() C.krb5_keyblock {
	return C.krb5_keyblock{
		enctype:  C.krb5_enctype(k.EncType),
		length:   C.uint(len(k.Contents)),
		contents: unsafeOctetPtr(k.Contents)}
}

// MakeRandomKey generates a random key for a given enctype.
func (ctx *Context) MakeRandomKey(encType EncType) (*KeyBlock, error) {
	var out C.krb5_keyblock
	if code := C.krb5_c_make_random_key(ctx.ctx, C.krb5_enctype(encType), &out); code != 0 {
		return nil, ctx.makeError(code)
	}
	defer C.krb5_free_keyblock_contents(ctx.ctx, &out)
	return keyBlockFromC(&out), nil
}

// MakeChecksum generates a checksum for the input keyed by a supplied key.
func (ctx *Context) MakeChecksum(sumType SumType, key *KeyBlock, usage int32, input []byte) (*Checksum, error) {
	var cksum C.krb5_checksum
	if code := C.make_checksum(ctx.ctx, C.krb5_cksumtype(sumType), key.toC(), C.krb5_keyusage(usage), bytesToKrb5DataAlias(input), &cksum); code != 0 {
		return nil, ctx.makeError(code)
	}
	defer C.krb5_free_checksum_contents(ctx.ctx, &cksum)
	return checksumFromC(&cksum), nil
}

// VerifyChecksum verifies a checksum given a key and parameters.
func (ctx *Context) VerifyChecksum(key *KeyBlock, usage int32, data []byte, checksum *Checksum) (bool, error) {
	var valid C.krb5_boolean
	if code := C.verify_checksum(ctx.ctx, key.toC(), C.krb5_keyusage(usage), bytesToKrb5DataAlias(data), checksum.toC(), &valid); code != 0 {
		return false, ctx.makeError(code)
	}
	return valid != 0, nil
}

// Keytabs

// A KeyTabEntry is a value type containing an entry from a KeyTab.
type KeyTabEntry struct {
	Principal    *Principal
	TimestampRaw int32
	Version      uint
	Key          *KeyBlock
}

func keyTabEntryFromC(kte *C.krb5_keytab_entry) *KeyTabEntry {
	return &KeyTabEntry{
		Principal:    principalFromC(kte.principal),
		TimestampRaw: int32(kte.timestamp),
		Version:      uint(kte.vno),
		Key:          keyBlockFromC(&kte.key)}
}

// Freed with freeKrb5KeytabEntry
func (kte *KeyTabEntry) toC(ctx *Context) C.krb5_keytab_entry {
	return C.krb5_keytab_entry{
		principal: kte.Principal.toCPtr(ctx),
		timestamp: C.krb5_timestamp(kte.TimestampRaw),
		vno:       C.krb5_kvno(kte.Version),
		key:       kte.Key.toC()}
}

func freeKrb5KeytabEntry(ctx *Context, kte *C.krb5_keytab_entry) {
	C.krb5_free_principal(ctx.ctx, kte.principal)
}

// A KeyTab wraps a krb5_keytab.
type KeyTab struct {
	context *Context
	keytab  C.krb5_keytab
}

// Close releases resources associated with a keytab.
func (kt *KeyTab) Close() error {
	if code := C.krb5_kt_close(kt.context.ctx, kt.keytab); code != 0 {
		kt.keytab = nil
		return kt.context.makeError(code)
	}
	kt.keytab = nil
	return nil
}

// Type returns the type of a keytab.
func (kt *KeyTab) Type() string {
	return C.GoString(C.krb5_kt_get_type(kt.context.ctx, kt.keytab))
}

// AddEntry adds a given entry to a keytab.
func (kt *KeyTab) AddEntry(kte *KeyTabEntry) error {
	kteC := kte.toC(kt.context)
	defer freeKrb5KeytabEntry(kt.context, &kteC)
	if code := C.kt_add_entry(kt.context.ctx, kt.keytab, kteC); code != 0 {
		return kt.context.makeError(code)
	}
	return nil
}

// GetEntry queries a keytab for an entry matching some parameters.
func (kt *KeyTab) GetEntry(princ *Principal, vno uint, enctype EncType) (*KeyTabEntry, error) {
	princC := princ.toC()
	defer freeKrb5PrincipalData(&princC)
	var kte C.krb5_keytab_entry
	if code := C.krb5_kt_get_entry(kt.context.ctx, kt.keytab, &princC, C.krb5_kvno(vno), C.krb5_enctype(enctype), &kte); code != 0 {
		return nil, kt.context.makeError(code)
	}
	defer C.krb5_free_keytab_entry_contents(kt.context.ctx, &kte)
	return keyTabEntryFromC(&kte), nil
}

// RemoveEntry removes a keytab entry from a keytab.
func (kt *KeyTab) RemoveEntry(kte *KeyTabEntry) error {
	kteC := kte.toC(kt.context)
	defer freeKrb5KeytabEntry(kt.context, &kteC)
	if code := C.kt_remove_entry(kt.context.ctx, kt.keytab, kteC); code != 0 {
		return kt.context.makeError(code)
	}
	return nil
}

// DefaultKeyTab opens the default keytab. It must be released by
// calling Close.
func (ctx *Context) DefaultKeyTab() (*KeyTab, error) {
	var keytab C.krb5_keytab
	if code := C.krb5_kt_default(ctx.ctx, &keytab); code != 0 {
		return nil, ctx.makeError(code)
	}
	return &KeyTab{context: ctx, keytab: keytab}, nil
}

// OpenKeyTab opens a keytab. It must be released by calling Close.
func (ctx *Context) OpenKeyTab(name string) (*KeyTab, error) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	keytab := C.krb5_keytab(nil)
	if code := C.krb5_kt_resolve(ctx.ctx, nameC, &keytab); code != 0 {
		return nil, ctx.makeError(code)
	}
	return &KeyTab{context: ctx, keytab: keytab}, nil
}

// CCache

// A CCache is a wrapper over a krb5_ccache object, a handle to a
// Kerberos credential cache.
type CCache struct {
	context *Context
	ccache  C.krb5_ccache
}

// Close releases resources associated with a ccache.
func (cc *CCache) Close() error {
	if code := C.krb5_cc_close(cc.context.ctx, cc.ccache); code != 0 {
		cc.ccache = nil
		return cc.context.makeError(code)
	}
	cc.ccache = nil
	return nil
}

// Type returns the type of the ccache.
func (cc *CCache) Type() string {
	return C.GoString(C.krb5_cc_get_type(cc.context.ctx, cc.ccache))
}

// Name returns the name of the ccache.
func (cc *CCache) Name() string {
	return C.GoString(C.krb5_cc_get_name(cc.context.ctx, cc.ccache))
}

// FullName returns the full name of the ccache.
func (cc *CCache) FullName() string {
	var out *C.char
	if code := C.krb5_cc_get_full_name(cc.context.ctx, cc.ccache, &out); code != 0 {
		panic(cc.context.makeError(code))
	}
	defer C.krb5_free_string(cc.context.ctx, out)
	return C.GoString(out)
}

// Principal returns the default principal of the ccache.
func (cc *CCache) Principal() (*Principal, error) {
	var out C.krb5_principal
	if code := C.krb5_cc_get_principal(cc.context.ctx, cc.ccache, &out); code != 0 {
		return nil, cc.context.makeError(code)
	}
	defer C.krb5_free_principal(cc.context.ctx, out)
	return principalFromC(out), nil
}

// DefaultCCache opens the default ccache for a context. The ccache
// must be released with Close.
func (ctx *Context) DefaultCCache() (*CCache, error) {
	var ccache C.krb5_ccache
	if code := C.krb5_cc_default(ctx.ctx, &ccache); code != 0 {
		return nil, ctx.makeError(code)
	}
	return &CCache{context: ctx, ccache: ccache}, nil
}

// OpenCCache opens a given ccache. It must be released with Close.
func (ctx *Context) OpenCCache(name string) (*CCache, error) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	var ccache C.krb5_ccache
	if code := C.krb5_cc_resolve(ctx.ctx, nameC, &ccache); code != 0 {
		return nil, ctx.makeError(code)
	}
	return &CCache{context: ctx, ccache: ccache}, nil
}

// Credentials.

// An Address is a value type that includes a krb5 address. These are
// basically unused.
type Address struct {
	Type     AddrType
	Contents []byte
}

// Freed with C.free(unsafe.Pointer(a.contents)).
func (a *Address) toC() C.krb5_address {
	return C.krb5_address{
		addrtype: C.krb5_addrtype(a.Type),
		length:   C.uint(len(a.Contents)),
		contents: cOctetPtr(a.Contents)}
}

func addressFromC(a *C.krb5_address) *Address {
	return &Address{
		Type: AddrType(a.addrtype),
		Contents: C.GoBytes(unsafe.Pointer(a.contents),
			C.int(a.length))}
}

// Freed with C.krb5_free_addresses.
func (ctx *Context) addressesToC(as []Address) **C.krb5_address {
	if len(as) == 0 {
		return nil
	}
	cArray := make([]C.krb5_address, 0, len(as))
	for _, a := range as {
		ca := a.toC()
		cArray = append(cArray, ca)
		defer C.free(unsafe.Pointer(ca.contents))
	}
	template := make([]*C.krb5_address, 0, len(as)+1)
	for i := range cArray {
		template = append(template, &cArray[i])
	}
	template = append(template, nil)
	out := (**C.krb5_address)(nil)
	if code := C.krb5_copy_addresses(ctx.ctx, &template[0], &out); code != 0 {
		panic(ctx.makeError(code))
	}
	return out
}

func addressesFromC(as **C.krb5_address) []Address {
	if as == nil {
		return nil
	}
	// Count them first.
	var num int
	asArray := (*[1 << 30]*C.krb5_address)(unsafe.Pointer(as))
	for num = 0; asArray[num] != nil; num++ {
	}
	asSlice := asArray[0:num]
	ret := make([]Address, 0, num)
	for _, v := range asSlice {
		ret = append(ret, *addressFromC(v))
	}
	return ret
}

// An AuthData is a value type that contains a Kerberos authorization
// data.
type AuthData struct {
	Type     int32
	Contents []byte
}

// Freed with C.free(unsafe.Pointer(a.contents)).
func (a *AuthData) toC() C.krb5_authdata {
	return C.krb5_authdata{
		ad_type:  C.krb5_authdatatype(a.Type),
		length:   C.uint(len(a.Contents)),
		contents: cOctetPtr(a.Contents)}
}

func authDataFromC(a *C.krb5_authdata) *AuthData {
	return &AuthData{
		Type: int32(a.ad_type),
		Contents: C.GoBytes(unsafe.Pointer(a.contents),
			C.int(a.length))}
}

// Freed with C.krb5_free_authdata.
func (ctx *Context) authDatasToC(as []AuthData) **C.krb5_authdata {
	if len(as) == 0 {
		return nil
	}
	cArray := make([]C.krb5_authdata, 0, len(as))
	for _, a := range as {
		ca := a.toC()
		cArray = append(cArray, ca)
		defer C.free(unsafe.Pointer(ca.contents))
	}
	template := make([]*C.krb5_authdata, 0, len(as)+1)
	for i := range cArray {
		template = append(template, &cArray[i])
	}
	template = append(template, nil)
	out := (**C.krb5_authdata)(nil)
	if code := C.krb5_copy_authdata(ctx.ctx, &template[0], &out); code != 0 {
		panic(ctx.makeError(code))
	}
	return out
}

func authDatasFromC(as **C.krb5_authdata) []AuthData {
	if as == nil {
		return nil
	}
	// Count them first.
	var num int
	asArray := (*[1 << 30]*C.krb5_authdata)(unsafe.Pointer(as))
	for num = 0; asArray[num] != nil; num++ {
	}
	asSlice := asArray[0:num]
	ret := make([]AuthData, 0, num)
	for _, v := range asSlice {
		ret = append(ret, *authDataFromC(v))
	}
	return ret
}

// A Credential is a value type containing a Kerberos credential.
type Credential struct {
	Client       *Principal
	Server       *Principal
	KeyBlock     *KeyBlock
	AuthTimeRaw  int32
	StartTimeRaw int32
	EndTimeRaw   int32
	RenewTillRaw int32
	IsSkey       bool
	Flags        int32
	Addresses    []Address
	Ticket       []byte
	SecondTicket []byte
	AuthData     []AuthData
}

// AuthTime returns the authentication time of the ticket.
func (c *Credential) AuthTime() time.Time {
	return time.Unix(int64(c.AuthTimeRaw), 0)
}

// HasStartTime returns whether the credential specifies a start time.
func (c *Credential) HasStartTime() bool {
	return c.StartTimeRaw != 0
}

// StartTime returns the start time of the ticket, falling back to the
// authentication time if not specified.
func (c *Credential) StartTime() time.Time {
	if c.HasStartTime() {
		return time.Unix(int64(c.StartTimeRaw), 0)
	}
	return c.AuthTime()
}

// EndTime returns the end time of the ticket.
func (c *Credential) EndTime() time.Time {
	return time.Unix(int64(c.EndTimeRaw), 0)
}

// HasRenewTill returns whether the credential specifies a renew time.
func (c *Credential) HasRenewTill() bool {
	return c.RenewTillRaw != 0
}

// RenewTill returns the renew limit of the ticket, falling back to
// the end time if not specified.
func (c *Credential) RenewTill() time.Time {
	if c.HasRenewTill() {
		return time.Unix(int64(c.RenewTillRaw), 0)
	}
	return c.EndTime()
}

// Freed with freeKrb5Creds.
func (c *Credential) toC(ctx *Context) C.krb5_creds {
	isSkey := 0
	if c.IsSkey {
		isSkey = 1
	}
	var kbc C.krb5_keyblock
	if c.KeyBlock != nil {
		kbc = c.KeyBlock.toC()
	}
	return C.krb5_creds{
		client:   c.Client.toCPtr(ctx),
		server:   c.Server.toCPtr(ctx),
		keyblock: kbc,
		times: C.krb5_ticket_times{
			authtime:   C.krb5_timestamp(c.AuthTimeRaw),
			starttime:  C.krb5_timestamp(c.StartTimeRaw),
			endtime:    C.krb5_timestamp(c.EndTimeRaw),
			renew_till: C.krb5_timestamp(c.RenewTillRaw)},
		is_skey:       C.krb5_boolean(isSkey),
		ticket_flags:  C.krb5_flags(c.Flags),
		addresses:     ctx.addressesToC(c.Addresses),
		ticket:        bytesToKrb5Data(c.Ticket),
		second_ticket: bytesToKrb5Data(c.SecondTicket),
		authdata:      ctx.authDatasToC(c.AuthData)}
}

func freeKrb5Creds(ctx *Context, c *C.krb5_creds) {
	C.krb5_free_principal(ctx.ctx, c.client)
	C.krb5_free_principal(ctx.ctx, c.server)
	freeKrb5Data(&c.ticket)
	freeKrb5Data(&c.second_ticket)
	if c.addresses != nil {
		C.krb5_free_addresses(ctx.ctx, c.addresses)
	}
	if c.authdata != nil {
		C.krb5_free_authdata(ctx.ctx, c.authdata)
	}
}

func credentialFromC(c *C.krb5_creds) *Credential {
	return &Credential{
		Client:       principalFromC(c.client),
		Server:       principalFromC(c.server),
		KeyBlock:     keyBlockFromC(&c.keyblock),
		AuthTimeRaw:  int32(c.times.authtime),
		StartTimeRaw: int32(c.times.starttime),
		EndTimeRaw:   int32(c.times.endtime),
		RenewTillRaw: int32(c.times.renew_till),
		IsSkey:       c.is_skey != 0,
		Flags:        int32(c.ticket_flags),
		Addresses:    addressesFromC(c.addresses),
		Ticket:       krb5DataToBytes(&c.ticket),
		SecondTicket: krb5DataToBytes(&c.second_ticket),
		AuthData:     authDatasFromC(c.authdata)}
}

// TODO(davidben): Write a second version with more options.
func (ctx *Context) GetInitialCredentialWithKeyTab(
	kt *KeyTab, client *Principal, service *Principal) (*Credential, error) {
	creds := C.krb5_creds{}
	clientC := client.toC()
	defer freeKrb5PrincipalData(&clientC)
	var serviceNameC *C.char
	if service != nil {
		serviceNameC = C.CString(service.String())
		defer C.free(unsafe.Pointer(serviceNameC))
	}
	if code := C.krb5_get_init_creds_keytab(ctx.ctx, &creds,
		&clientC, kt.keytab, 0, serviceNameC, nil); code != 0 {
		return nil, ctx.makeError(code)
	}
	defer C.krb5_free_cred_contents(ctx.ctx, &creds)
	return credentialFromC(&creds), nil
}

// TODO(davidben): Expose more of these options.
func (ctx *Context) GetCredential(
	cc *CCache, client *Principal, service *Principal) (*Credential, error) {
	inCredsG := Credential{Client: client, Server: service}
	inCreds := inCredsG.toC(ctx)
	defer freeKrb5Creds(ctx, &inCreds)
	var outCreds *C.krb5_creds
	if code := C.krb5_get_credentials(ctx.ctx, 0, cc.ccache, &inCreds, &outCreds); code != 0 {
		return nil, ctx.makeError(code)
	}
	defer C.krb5_free_creds(ctx.ctx, outCreds)
	return credentialFromC(outCreds), nil
}

// Authentication contexts

type AuthContext struct {
	context     *Context
	authcontext C.krb5_auth_context
}

func (ctx *Context) NewAuthContext() (*AuthContext, error) {
	ac := C.krb5_auth_context(nil)
	if code := C.krb5_auth_con_init(ctx.ctx, &ac); code != 0 {
		return nil, ctx.makeError(code)
	}
	return &AuthContext{context: ctx, authcontext: ac}, nil
}

func (ac *AuthContext) Free() {
	C.krb5_auth_con_free(ac.context.ctx, ac.authcontext)
	ac.authcontext = nil
}

func (ac *AuthContext) flags() int32 {
	var flags C.krb5_int32
	if code := C.krb5_auth_con_getflags(
		ac.context.ctx, ac.authcontext, &flags); code != 0 {
		// This should never fail.
		panic(ac.context.makeError(code))
	}
	return int32(flags)
}

func (ac *AuthContext) setFlags(flags int32) {
	if code := C.krb5_auth_con_setflags(
		ac.context.ctx, ac.authcontext, C.krb5_int32(flags)); code != 0 {
		// This should never fail.
		panic(ac.context.makeError(code))
	}
}

func (ac *AuthContext) flag(flag int32) bool {
	return (ac.flags() & flag) != 0
}

func (ac *AuthContext) setFlag(flag int32, value bool) {
	flags := ac.flags()
	if value {
		flags |= flag
	} else {
		flags &^= flag
	}
	ac.setFlags(flags)
}

func (ac *AuthContext) UseTimestamps() bool {
	return ac.flag(C.KRB5_AUTH_CONTEXT_DO_TIME)
}

func (ac *AuthContext) SetUseTimestamps(value bool) {
	ac.setFlag(C.KRB5_AUTH_CONTEXT_DO_TIME, value)
}

func (ac *AuthContext) SaveTimestamps() bool {
	return ac.flag(C.KRB5_AUTH_CONTEXT_RET_TIME)
}

func (ac *AuthContext) SetSaveTimestamps(value bool) {
	ac.setFlag(C.KRB5_AUTH_CONTEXT_RET_TIME, value)
}

func (ac *AuthContext) UseSequenceNumbers() bool {
	return ac.flag(C.KRB5_AUTH_CONTEXT_DO_SEQUENCE)
}

func (ac *AuthContext) SetUseSequenceNumbers(value bool) {
	ac.setFlag(C.KRB5_AUTH_CONTEXT_DO_SEQUENCE, value)
}

func (ac *AuthContext) SaveSequenceNumbers() bool {
	return ac.flag(C.KRB5_AUTH_CONTEXT_RET_SEQUENCE)
}

func (ac *AuthContext) SetSaveSequenceNumbers(value bool) {
	ac.setFlag(C.KRB5_AUTH_CONTEXT_RET_SEQUENCE, value)
}

func (ac *AuthContext) SessionKey() (*KeyBlock, error) {
	var key *C.krb5_keyblock
	if code := C.krb5_auth_con_getkey(ac.context.ctx, ac.authcontext, &key); code != 0 {
		return nil, ac.context.makeError(code)
	}
	defer C.krb5_free_keyblock(ac.context.ctx, key)
	return keyBlockFromC(key), nil
}

func (ac *AuthContext) MakeRequest(
	cred *Credential, options int32, data []byte) ([]byte, error) {
	var dataC *C.krb5_data
	if data != nil {
		d := bytesToKrb5Data(data)
		defer freeKrb5Data(&d)
		dataC = &d
	}
	credC := cred.toC(ac.context)
	defer freeKrb5Creds(ac.context, &credC)
	out := C.krb5_data{}
	if code := C.mk_req_extended(ac.context.ctx, &ac.authcontext,
		C.krb5_flags(options), dataC, credC, &out); code != 0 {
		return nil, ac.context.makeError(code)
	}
	defer C.krb5_free_data_contents(ac.context.ctx, &out)
	return krb5DataToBytes(&out), nil
}

// TODO(davidben): Return ap_req_options and ticket output parameters?
func (ac *AuthContext) ReadRequest(
	request []byte, server *Principal, keytab *KeyTab) error {
	var serverC C.krb5_principal
	if server != nil {
		serverCData := server.toC()
		serverC = &serverCData
		defer freeKrb5PrincipalData(serverC)
	}

	var keytabC C.krb5_keytab
	if keytab != nil {
		keytabC = keytab.keytab
	}

	requestC := bytesToKrb5Data(request)
	defer freeKrb5Data(&requestC)

	if code := C.krb5_rd_req(ac.context.ctx, &ac.authcontext,
		&requestC, serverC, keytabC, nil, nil); code != 0 {
		return ac.context.makeError(code)
	}
	return nil
}

// Convenience function
func (ctx *Context) MakeRequest(
	cred *Credential, options int32, data []byte) ([]byte, error) {
	ac, error := ctx.NewAuthContext()
	if error != nil {
		return nil, error
	}
	defer ac.Free()
	return ac.MakeRequest(cred, options, data)
}
