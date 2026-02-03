package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
)

// JA3 指纹组件
type JA3Components struct {
	TLSVersion      uint16
	CipherSuites    []uint16
	Extensions      []uint16
	EllipticCurves  []uint16
	ECPointFormats  []uint8
}

// 生成 JA3 字符串
func (j *JA3Components) String() string {
	ciphers := uint16SliceToString(j.CipherSuites)
	extensions := uint16SliceToString(j.Extensions)
	curves := uint16SliceToString(j.EllipticCurves)
	formats := uint8SliceToString(j.ECPointFormats)

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		j.TLSVersion, ciphers, extensions, curves, formats)
}

// 计算 JA3 哈希
func (j *JA3Components) Hash() string {
	h := md5.Sum([]byte(j.String()))
	return hex.EncodeToString(h[:])
}

func uint16SliceToString(s []uint16) string {
	strs := make([]string, len(s))
	for i, v := range s {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, "-")
}

func uint8SliceToString(s []uint8) string {
	strs := make([]string, len(s))
	for i, v := range s {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, "-")
}

// 常用的 Cipher Suites
var commonCipherSuites = []uint16{
	// TLS 1.3
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256

	// TLS 1.2 ECDHE
	0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

	// TLS 1.2 DHE
	0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

	// Legacy
	0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
}

// 常用的 Extensions
var commonExtensions = []uint16{
	0x0000, // server_name
	0x0017, // extended_master_secret
	0xff01, // renegotiation_info
	0x000a, // supported_groups
	0x000b, // ec_point_formats
	0x0023, // session_ticket
	0x0010, // application_layer_protocol_negotiation
	0x0005, // status_request
	0x000d, // signature_algorithms
	0x0012, // signed_certificate_timestamp
	0x0033, // key_share
	0x002d, // psk_key_exchange_modes
	0x002b, // supported_versions
	0x001b, // compress_certificate
	0x0015, // padding
}

// 常用的椭圆曲线
var commonCurves = []uint16{
	0x001d, // x25519
	0x0017, // secp256r1
	0x0018, // secp384r1
	0x0019, // secp521r1
}

// EC Point Formats
var commonECPointFormats = []uint8{
	0x00, // uncompressed
}

// 生成随机 JA3 组件
func GenerateRandomJA3() *JA3Components {
	// 随机选择 TLS 版本
	versions := []uint16{0x0303, 0x0304} // TLS 1.2, TLS 1.3
	version := versions[rand.Intn(len(versions))]

	// 随机选择并打乱 cipher suites
	numCiphers := rand.Intn(8) + 5 // 5-12 个
	ciphers := make([]uint16, numCiphers)
	perm := rand.Perm(len(commonCipherSuites))
	for i := 0; i < numCiphers && i < len(perm); i++ {
		ciphers[i] = commonCipherSuites[perm[i]]
	}

	// 可能添加 GREASE 值
	if rand.Float32() < 0.7 {
		greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
		grease := greaseValues[rand.Intn(len(greaseValues))]
		ciphers = append([]uint16{grease}, ciphers...)
	}

	// 随机选择并打乱 extensions
	numExtensions := rand.Intn(6) + 8 // 8-13 个
	extensions := make([]uint16, numExtensions)
	perm = rand.Perm(len(commonExtensions))
	for i := 0; i < numExtensions && i < len(perm); i++ {
		extensions[i] = commonExtensions[perm[i]]
	}

	// 可能添加 GREASE 到 extensions
	if rand.Float32() < 0.7 {
		greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a}
		grease := greaseValues[rand.Intn(len(greaseValues))]
		extensions = append([]uint16{grease}, extensions...)
	}

	// 随机选择椭圆曲线
	numCurves := rand.Intn(2) + 2 // 2-3 个
	curves := make([]uint16, numCurves)
	perm = rand.Perm(len(commonCurves))
	for i := 0; i < numCurves && i < len(perm); i++ {
		curves[i] = commonCurves[perm[i]]
	}

	// 可能添加 GREASE 到 curves
	if rand.Float32() < 0.5 {
		greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a}
		grease := greaseValues[rand.Intn(len(greaseValues))]
		curves = append([]uint16{grease}, curves...)
	}

	return &JA3Components{
		TLSVersion:      version,
		CipherSuites:    ciphers,
		Extensions:      extensions,
		EllipticCurves:  curves,
		ECPointFormats:  commonECPointFormats,
	}
}

// Chrome 120 的 JA3 组件
func ChromeJA3() *JA3Components {
	return &JA3Components{
		TLSVersion: 0x0303,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
		},
		EllipticCurves:  []uint16{0x001d, 0x0017, 0x0018},
		ECPointFormats:  []uint8{0x00},
	}
}

// Firefox 120 的 JA3 组件
func FirefoxJA3() *JA3Components {
	return &JA3Components{
		TLSVersion: 0x0303,
		CipherSuites: []uint16{
			0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
			0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d,
			0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x0015,
		},
		EllipticCurves:  []uint16{0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101},
		ECPointFormats:  []uint8{0x00},
	}
}

// Safari 17 的 JA3 组件
func SafariJA3() *JA3Components {
	return &JA3Components{
		TLSVersion: 0x0303,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030,
			0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c,
			0x0035, 0x002f,
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
			0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
		},
		EllipticCurves:  []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		ECPointFormats:  []uint8{0x00},
	}
}

// 根据指纹 ID 获取 JA3 组件
func GetJA3ByID(id string) *JA3Components {
	switch id {
	case "chrome_120", "chrome_110":
		return ChromeJA3()
	case "firefox_120", "firefox_110":
		return FirefoxJA3()
	case "safari_17":
		return SafariJA3()
	case "random", "random_per_request":
		return GenerateRandomJA3()
	default:
		return GenerateRandomJA3()
	}
}

// 打乱切片顺序
func shuffleUint16(s []uint16) {
	rand.Shuffle(len(s), func(i, j int) {
		s[i], s[j] = s[j], s[i]
	})
}

// 对切片排序（用于 JA4）
func sortUint16(s []uint16) []uint16 {
	sorted := make([]uint16, len(s))
	copy(sorted, s)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	return sorted
}
