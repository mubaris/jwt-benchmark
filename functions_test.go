package main

import (
	"testing"
)

func BenchmarkVerifyJwt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		VerifyJwt()
	}
}

func BenchmarkVerifyJose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		VerifyJose()
	}
}

func BenchmarkSignJwt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SignJwt()
	}
}

func BenchmarkSignJose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SignJose()
	}
}

func BenchmarkVerifyJwtWithToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		VerifyJwtWithToken()
	}
}

func BenchmarkVerifyJoseWithToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		VerifyJoseWithToken()
	}
}
