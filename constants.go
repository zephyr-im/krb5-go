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

package krb5

// #cgo LDFLAGS: -lkrb5 -lk5crypto -lcom_err
// #include <krb5.h>
import "C"
import "strconv"

type NameType int32

const (
	NT_UNKNOWN              NameType = C.KRB5_NT_UNKNOWN
	NT_PRINCIPAL            NameType = C.KRB5_NT_PRINCIPAL
	NT_SRV_INST             NameType = C.KRB5_NT_SRV_INST
	NT_SRV_HST              NameType = C.KRB5_NT_SRV_HST
	NT_SRV_XHST             NameType = C.KRB5_NT_SRV_XHST
	NT_UID                  NameType = C.KRB5_NT_UID
	NT_X500_PRINCIPAL       NameType = C.KRB5_NT_X500_PRINCIPAL
	NT_SMTP_NAME            NameType = C.KRB5_NT_SMTP_NAME
	NT_ENTERPRISE_PRINCIPAL NameType = C.KRB5_NT_ENTERPRISE_PRINCIPAL
	NT_WELLKNOWN            NameType = C.KRB5_NT_WELLKNOWN
	NT_MS_PRINCIPAL         NameType = C.KRB5_NT_MS_PRINCIPAL
	NT_MS_PRINCIPAL_AND_ID  NameType = C.KRB5_NT_MS_PRINCIPAL_AND_ID
	NT_ENT_PRINCIPAL_AND_ID NameType = C.KRB5_NT_ENT_PRINCIPAL_AND_ID
)

func (n NameType) String() string {
	switch n {
	case NT_UNKNOWN:
		return "NT_UNKNOWN"
	case NT_PRINCIPAL:
		return "NT_PRINCIPAL"
	case NT_SRV_INST:
		return "NT_SRV_INST"
	case NT_SRV_HST:
		return "NT_SRV_HST"
	case NT_SRV_XHST:
		return "NT_SRV_XHST"
	case NT_UID:
		return "NT_UID"
	case NT_X500_PRINCIPAL:
		return "NT_X500_PRINCIPAL"
	case NT_SMTP_NAME:
		return "NT_SMTP_NAME"
	case NT_ENTERPRISE_PRINCIPAL:
		return "NT_ENTERPRISE_PRINCIPAL"
	case NT_WELLKNOWN:
		return "NT_WELLKNOWN"
	case NT_MS_PRINCIPAL:
		return "NT_MS_PRINCIPAL"
	case NT_MS_PRINCIPAL_AND_ID:
		return "NT_MS_PRINCIPAL_AND_ID"
	case NT_ENT_PRINCIPAL_AND_ID:
		return "NT_ENT_PRINCIPAL_AND_ID"
	default:
		return strconv.Itoa(int(n))
	}
}

type AddrType int32

const (
	AddrTypeINET     AddrType = C.ADDRTYPE_INET
	AddrTypeChaos    AddrType = C.ADDRTYPE_CHAOS
	AddrTypeXNS      AddrType = C.ADDRTYPE_XNS
	AddrTypeISO      AddrType = C.ADDRTYPE_ISO
	AddrTypeDDP      AddrType = C.ADDRTYPE_DDP
	AddrTypeNetBIOS  AddrType = C.ADDRTYPE_NETBIOS
	AddrTypeINET6    AddrType = C.ADDRTYPE_INET6
	AddrTypeAddrPort AddrType = C.ADDRTYPE_ADDRPORT
	AddrTypeIPPort   AddrType = C.ADDRTYPE_IPPORT
)

func (a AddrType) String() string {
	switch a {
	case AddrTypeINET:
		return "AddrTypeINET"
	case AddrTypeChaos:
		return "AddrTypeChaos"
	case AddrTypeXNS:
		return "AddrTypeXNS"
	case AddrTypeISO:
		return "AddrTypeISO"
	case AddrTypeDDP:
		return "AddrTypeDDP"
	case AddrTypeNetBIOS:
		return "AddrTypeNetBIOS"
	case AddrTypeINET6:
		return "AddrTypeINET6"
	case AddrTypeAddrPort:
		return "AddrTypeAddrPort"
	case AddrTypeIPPort:
		return "AddrTypeIPPort"
	default:
		return strconv.Itoa(int(a))
	}
}

const (
	APOptsUseSessionKey  = C.AP_OPTS_USE_SESSION_KEY
	APOptsMutualRequired = C.AP_OPTS_MUTUAL_REQUIRED
	APOptsUseSubkey      = C.AP_OPTS_USE_SUBKEY
)

type EncType int32

const (
	ENCTYPE_NULL                    EncType = C.ENCTYPE_NULL
	ENCTYPE_DES_CBC_CRC             EncType = C.ENCTYPE_DES_CBC_CRC
	ENCTYPE_DES_CBC_MD4             EncType = C.ENCTYPE_DES_CBC_MD4
	ENCTYPE_DES_CBC_MD5             EncType = C.ENCTYPE_DES_CBC_MD5
	ENCTYPE_DES_CBC_RAW             EncType = C.ENCTYPE_DES_CBC_RAW
	ENCTYPE_DES3_CBC_SHA            EncType = C.ENCTYPE_DES3_CBC_SHA
	ENCTYPE_DES3_CBC_RAW            EncType = C.ENCTYPE_DES3_CBC_RAW
	ENCTYPE_DES_HMAC_SHA1           EncType = C.ENCTYPE_DES_HMAC_SHA1
	ENCTYPE_DSA_SHA1_CMS            EncType = C.ENCTYPE_DSA_SHA1_CMS
	ENCTYPE_MD5_RSA_CMS             EncType = C.ENCTYPE_MD5_RSA_CMS
	ENCTYPE_SHA1_RSA_CMS            EncType = C.ENCTYPE_SHA1_RSA_CMS
	ENCTYPE_RC2_CBC_ENV             EncType = C.ENCTYPE_RC2_CBC_ENV
	ENCTYPE_RSA_ENV                 EncType = C.ENCTYPE_RSA_ENV
	ENCTYPE_RSA_ES_OAEP_ENV         EncType = C.ENCTYPE_RSA_ES_OAEP_ENV
	ENCTYPE_DES3_CBC_ENV            EncType = C.ENCTYPE_DES3_CBC_ENV
	ENCTYPE_DES3_CBC_SHA1           EncType = C.ENCTYPE_DES3_CBC_SHA1
	ENCTYPE_AES128_CTS_HMAC_SHA1_96 EncType = C.ENCTYPE_AES128_CTS_HMAC_SHA1_96
	ENCTYPE_AES256_CTS_HMAC_SHA1_96 EncType = C.ENCTYPE_AES256_CTS_HMAC_SHA1_96
	ENCTYPE_ARCFOUR_HMAC            EncType = C.ENCTYPE_ARCFOUR_HMAC
	ENCTYPE_ARCFOUR_HMAC_EXP        EncType = C.ENCTYPE_ARCFOUR_HMAC_EXP
	ENCTYPE_UNKNOWN                 EncType = C.ENCTYPE_UNKNOWN
)

func (e EncType) String() string {
	switch e {
	case ENCTYPE_NULL:
		return "ENCTYPE_NULL"
	case ENCTYPE_DES_CBC_CRC:
		return "ENCTYPE_DES_CBC_CRC"
	case ENCTYPE_DES_CBC_MD4:
		return "ENCTYPE_DES_CBC_MD4"
	case ENCTYPE_DES_CBC_MD5:
		return "ENCTYPE_DES_CBC_MD5"
	case ENCTYPE_DES_CBC_RAW:
		return "ENCTYPE_DES_CBC_RAW"
	case ENCTYPE_DES3_CBC_SHA:
		return "ENCTYPE_DES3_CBC_SHA"
	case ENCTYPE_DES3_CBC_RAW:
		return "ENCTYPE_DES3_CBC_RAW"
	case ENCTYPE_DES_HMAC_SHA1:
		return "ENCTYPE_DES_HMAC_SHA1"
	case ENCTYPE_DSA_SHA1_CMS:
		return "ENCTYPE_DSA_SHA1_CMS"
	case ENCTYPE_MD5_RSA_CMS:
		return "ENCTYPE_MD5_RSA_CMS"
	case ENCTYPE_SHA1_RSA_CMS:
		return "ENCTYPE_SHA1_RSA_CMS"
	case ENCTYPE_RC2_CBC_ENV:
		return "ENCTYPE_RC2_CBC_ENV"
	case ENCTYPE_RSA_ENV:
		return "ENCTYPE_RSA_ENV"
	case ENCTYPE_RSA_ES_OAEP_ENV:
		return "ENCTYPE_RSA_ES_OAEP_ENV"
	case ENCTYPE_DES3_CBC_ENV:
		return "ENCTYPE_DES3_CBC_ENV"
	case ENCTYPE_DES3_CBC_SHA1:
		return "ENCTYPE_DES3_CBC_SHA1"
	case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		return "ENCTYPE_AES128_CTS_HMAC_SHA1_96"
	case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		return "ENCTYPE_AES256_CTS_HMAC_SHA1_96"
	case ENCTYPE_ARCFOUR_HMAC:
		return "ENCTYPE_ARCFOUR_HMAC"
	case ENCTYPE_ARCFOUR_HMAC_EXP:
		return "ENCTYPE_ARCFOUR_HMAC_EXP"
	case ENCTYPE_UNKNOWN:
		return "ENCTYPE_UNKNOWN"
	default:
		return strconv.Itoa(int(e))
	}
}

type SumType int32

const (
	SUMTYPE_DEFAULT             SumType = 0
	SUMTYPE_CRC32               SumType = C.CKSUMTYPE_CRC32
	SUMTYPE_RSA_MD4             SumType = C.CKSUMTYPE_RSA_MD4
	SUMTYPE_RSA_MD4_DES         SumType = C.CKSUMTYPE_RSA_MD4_DES
	SUMTYPE_DESCBC              SumType = C.CKSUMTYPE_DESCBC
	SUMTYPE_RSA_MD5             SumType = C.CKSUMTYPE_RSA_MD5
	SUMTYPE_RSA_MD5_DES         SumType = C.CKSUMTYPE_RSA_MD5_DES
	SUMTYPE_NIST_SHA            SumType = C.CKSUMTYPE_NIST_SHA
	SUMTYPE_HMAC_SHA1_DES3      SumType = C.CKSUMTYPE_HMAC_SHA1_DES3
	SUMTYPE_HMAC_SHA1_96_AES128 SumType = C.CKSUMTYPE_HMAC_SHA1_96_AES128
	SUMTYPE_HMAC_SHA1_96_AES256 SumType = C.CKSUMTYPE_HMAC_SHA1_96_AES256
	SUMTYPE_MD5_HMAC_ARCFOUR    SumType = C.CKSUMTYPE_MD5_HMAC_ARCFOUR
	SUMTYPE_HMAC_MD5_ARCFOUR    SumType = C.CKSUMTYPE_HMAC_MD5_ARCFOUR
)

func (s SumType) String() string {
	switch s {
	case SUMTYPE_CRC32:
		return "SUMTYPE_CRC32"
	case SUMTYPE_RSA_MD4:
		return "SUMTYPE_RSA_MD4"
	case SUMTYPE_RSA_MD4_DES:
		return "SUMTYPE_RSA_MD4_DES"
	case SUMTYPE_DESCBC:
		return "SUMTYPE_DESCBC"
	case SUMTYPE_RSA_MD5:
		return "SUMTYPE_RSA_MD5"
	case SUMTYPE_RSA_MD5_DES:
		return "SUMTYPE_RSA_MD5_DES"
	case SUMTYPE_NIST_SHA:
		return "SUMTYPE_NIST_SHA"
	case SUMTYPE_HMAC_SHA1_DES3:
		return "SUMTYPE_HMAC_SHA1_DES3"
	case SUMTYPE_HMAC_SHA1_96_AES128:
		return "SUMTYPE_HMAC_SHA1_96_AES128"
	case SUMTYPE_HMAC_SHA1_96_AES256:
		return "SUMTYPE_HMAC_SHA1_96_AES256"
	case SUMTYPE_MD5_HMAC_ARCFOUR:
		return "SUMTYPE_MD5_HMAC_ARCFOUR"
	case SUMTYPE_HMAC_MD5_ARCFOUR:
		return "SUMTYPE_HMAC_MD5_ARCFOUR"
	default:
		return strconv.Itoa(int(s))
	}
}

func (s SumType) IsKeyed() bool {
	return C.krb5_c_is_keyed_cksum(C.krb5_cksumtype(s)) != 0
}

func (s SumType) IsCollisionProof() bool {
	return C.krb5_c_is_coll_proof_cksum(C.krb5_cksumtype(s)) != 0
}

const (
	KEYUSAGE_AS_REQ_PA_ENC_TS         = C.KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS
	KEYUSAGE_KDC_REP_TICKET           = C.KRB5_KEYUSAGE_KDC_REP_TICKET
	KEYUSAGE_AS_REP_ENCPART           = C.KRB5_KEYUSAGE_AS_REP_ENCPART
	KEYUSAGE_TGS_REQ_AD_SESSKEY       = C.KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY
	KEYUSAGE_TGS_REQ_AD_SUBKEY        = C.KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY
	KEYUSAGE_TGS_REQ_AUTH_CKSUM       = C.KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM
	KEYUSAGE_TGS_REQ_AUTH             = C.KRB5_KEYUSAGE_TGS_REQ_AUTH
	KEYUSAGE_TGS_REP_ENCPART_SESSKEY  = C.KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY
	KEYUSAGE_TGS_REP_ENCPART_SUBKEY   = C.KRB5_KEYUSAGE_TGS_REP_ENCPART_SUBKEY
	KEYUSAGE_AP_REQ_AUTH_CKSUM        = C.KRB5_KEYUSAGE_AP_REQ_AUTH_CKSUM
	KEYUSAGE_AP_REQ_AUTH              = C.KRB5_KEYUSAGE_AP_REQ_AUTH
	KEYUSAGE_AP_REP_ENCPART           = C.KRB5_KEYUSAGE_AP_REP_ENCPART
	KEYUSAGE_KRB_PRIV_ENCPART         = C.KRB5_KEYUSAGE_KRB_PRIV_ENCPART
	KEYUSAGE_KRB_CRED_ENCPART         = C.KRB5_KEYUSAGE_KRB_CRED_ENCPART
	KEYUSAGE_KRB_SAFE_CKSUM           = C.KRB5_KEYUSAGE_KRB_SAFE_CKSUM
	KEYUSAGE_APP_DATA_ENCRYPT         = C.KRB5_KEYUSAGE_APP_DATA_ENCRYPT
	KEYUSAGE_APP_DATA_CKSUM           = C.KRB5_KEYUSAGE_APP_DATA_CKSUM
	KEYUSAGE_KRB_ERROR_CKSUM          = C.KRB5_KEYUSAGE_KRB_ERROR_CKSUM
	KEYUSAGE_AD_KDCISSUED_CKSUM       = C.KRB5_KEYUSAGE_AD_KDCISSUED_CKSUM
	KEYUSAGE_AD_MTE                   = C.KRB5_KEYUSAGE_AD_MTE
	KEYUSAGE_AD_ITE                   = C.KRB5_KEYUSAGE_AD_ITE
	KEYUSAGE_GSS_TOK_MIC              = C.KRB5_KEYUSAGE_GSS_TOK_MIC
	KEYUSAGE_GSS_TOK_WRAP_INTEG       = C.KRB5_KEYUSAGE_GSS_TOK_WRAP_INTEG
	KEYUSAGE_GSS_TOK_WRAP_PRIV        = C.KRB5_KEYUSAGE_GSS_TOK_WRAP_PRIV
	KEYUSAGE_PA_SAM_CHALLENGE_CKSUM   = C.KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM
	KEYUSAGE_PA_SAM_CHALLENGE_TRACKID = C.KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRACKID
	KEYUSAGE_PA_SAM_RESPONSE          = C.KRB5_KEYUSAGE_PA_SAM_RESPONSE
	KEYUSAGE_PA_REFERRAL              = C.KRB5_KEYUSAGE_PA_REFERRAL
	KEYUSAGE_PA_S4U_X509_USER_REQUEST = C.KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST
	KEYUSAGE_PA_S4U_X509_USER_REPLY   = C.KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY
	KEYUSAGE_AD_SIGNEDPATH            = C.KRB5_KEYUSAGE_AD_SIGNEDPATH
	KEYUSAGE_IAKERB_FINISHED          = C.KRB5_KEYUSAGE_IAKERB_FINISHED
	KEYUSAGE_PA_PKINIT_KX             = C.KRB5_KEYUSAGE_PA_PKINIT_KX
	KEYUSAGE_FAST_REQ_CHKSUM          = C.KRB5_KEYUSAGE_FAST_REQ_CHKSUM
	KEYUSAGE_FAST_ENC                 = C.KRB5_KEYUSAGE_FAST_ENC
	KEYUSAGE_FAST_REP                 = C.KRB5_KEYUSAGE_FAST_REP
	KEYUSAGE_FAST_FINISHED            = C.KRB5_KEYUSAGE_FAST_FINISHED
	KEYUSAGE_ENC_CHALLENGE_CLIENT     = C.KRB5_KEYUSAGE_ENC_CHALLENGE_CLIENT
	KEYUSAGE_ENC_CHALLENGE_KDC        = C.KRB5_KEYUSAGE_ENC_CHALLENGE_KDC
	KEYUSAGE_AS_REQ                   = C.KRB5_KEYUSAGE_AS_REQ
)
