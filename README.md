# jwt-benchmark

Benchmarking 2 JWT libraries in Golang.

* [github.com/dgrijalva/jwt-go](github.com/dgrijalva/jwt-go)
* [github.com/dvsekhvalnov/jose2go](github.com/dvsekhvalnov/jose2go)

## Results

```
$ go test -bench=. -timeout=20m -benchtime=30s -benchmem
  goos: linux
  goarch: amd64
  pkg: github.com/mubaris/jwt-benchmark
  BenchmarkVerifyJwt           	  200000	    299809 ns/op	   43416 B/op	     178 allocs/op
  BenchmarkVerifyJose          	  200000	    286473 ns/op	   45512 B/op	     136 allocs/op
  BenchmarkSignJwt             	    2000	  30956351 ns/op	  148464 B/op	     374 allocs/op
  BenchmarkSignJose            	    2000	  30964100 ns/op	  155207 B/op	     397 allocs/op
  BenchmarkVerifyJwtWithToken  	    2000	  31499482 ns/op	  192137 B/op	     554 allocs/op
  BenchmarkVerifyJoseWithToken 	    2000	  31602349 ns/op	  201454 B/op	     536 allocs/op
  PASS
  ok  	github.com/mubaris/jwt-benchmark	385.868s
```
