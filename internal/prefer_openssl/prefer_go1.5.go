// +build !go1.6
// = go 1.5 or lower

package prefer_openssl

func PreferOpenSSL() bool {
	// OpenSSL is always faster than Go GCM on old Go versions.
	return true
}
