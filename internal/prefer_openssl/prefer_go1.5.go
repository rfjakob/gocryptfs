// +build !go1.6,!go1.7 !amd64
// not go1.6+ OR not amd64

package prefer_openssl

// PreferOpenSSL returns true if OpenSSL should be used.
func PreferOpenSSL() bool {
	// OpenSSL is always faster than Go GCM on old Go versions or on anything
	// other than amd64
	return true
}
