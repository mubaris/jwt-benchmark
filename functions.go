package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
	"unsafe"

	jwt "github.com/dgrijalva/jwt-go"
	jose "github.com/dvsekhvalnov/jose2go"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

type ModifiedClaims struct {
	jwt.StandardClaims
	Scopes []string `json:"scopes"`
}

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func SignJose() string {
	jti := RandStringBytesMaskImprSrcUnsafe(80)
	iat := int32(time.Now().UTC().Unix())
	exp := int32(time.Now().AddDate(0, 1, 0).UTC().Unix())
	payload := fmt.Sprintf(`{"aud":"1","jti":"%s","iat":%d,"nbf":%d,"exp":%d,"sub":"4001","scopes":[]}`, jti, iat, iat, exp)

	keyBytes, err := ioutil.ReadFile("rsa_private.pem")

	if err != nil {
		panic("invalid key file")
	}

	privateKey, e := Rsa.ReadPrivate(keyBytes)

	if e != nil {
		panic("invalid key format")
	}

	token, err := jose.Sign(payload, jose.RS256, privateKey,
		jose.Header("typ", "JWT"),
		jose.Header("jti", jti))
	if e != nil {
		panic("error while creating token")
	}

	return token
}

func SignJwt() string {
	var (
		signKey *rsa.PrivateKey
	)

	signBytes, err := ioutil.ReadFile("rsa_private.pem")

	if err != nil {
		panic("invalid key file")
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)

	if err != nil {
		panic("invalid key format")
	}

	jti := RandStringBytesMaskImprSrcUnsafe(80)

	claims := &ModifiedClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  int64(time.Now().UTC().Unix()),
			NotBefore: int64(time.Now().UTC().Unix()),
			ExpiresAt: int64(time.Now().AddDate(0, 1, 0).UTC().Unix()),
			Audience:  "1",
			Id:        jti,
			Subject:   "4001",
		},
		Scopes: []string{},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["jti"] = jti
	token, err := t.SignedString(signKey)

	if err != nil {
		panic(err.Error())
	}

	return token
}

func VerifyJwt() {

	var (
		verifyKey *rsa.PublicKey
	)

	tokenValue := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjVlYTRiYmY4ZmEwOTgzOTg3ZDI5MmU2MjAzNzMwNjQ5Y2M1ZGE3ZGNmZmZmNDEwMDlhZjllMzNjY2UzMjU1NGEwN2I1MGRjOWVlMmUxYWJiIn0.eyJhdWQiOiIxIiwianRpIjoiNWVhNGJiZjhmYTA5ODM5ODdkMjkyZTYyMDM3MzA2NDljYzVkYTdkY2ZmZmY0MTAwOWFmOWUzM2NjZTMyNTU0YTA3YjUwZGM5ZWUyZTFhYmIiLCJpYXQiOjE1NjM2MzQ4NzksIm5iZiI6MTU2MzYzNDg3OSwiZXhwIjoxNTk1MjU3Mjc5LCJzdWIiOiI2NCIsInNjb3BlcyI6W119.oWFAa5gy1eB_HoNoGVUCDSoWWTceWdP-1UKJzn81Y4IQtKYUQuw37wm63VVSZsf7kz1K2r1T93k4oYijyMjHupj4LDaoO2pD0nlIorSoDwIYgF-MkFwSv0FacdECswYBLi_yUiBwaMF7k6QaI5BrCjsqFsqiYCM-7JPa5xdEmD3JXr5QQmizWHb6c6ggv7TNQCW_S8MlblTTbl4izINTfb7u2K8jgJ9cpeapAGmfAMHFamCSXEPOzpfiDxdAIXRT7f5w58yYsT2ng3YuTE_M6f4nuwTNxGN907N-x5JJbcLEuL3Tykd11F9fuU4AimacCsSf3M8L0e15gr8dmhaUy3the4uTKTmD8bFTtqYs87DT6guVokrnQNphhGDE2VT9dr6MyX0ap_RpWDcbkYDMzMfjLcWRcSywNKH93QAO5kquNLUyGiWa4r4uqbe7E6w6fESOoJGvTkWQ85-x6bl9aw_NgNz-UIa0TO-I1SNGvpckMnTekD5RMPquDrhXxGMpw_A-B5SXWcsRPMnS-dDH5DjDf1mRgsfNJg-iGYZ6Rk9PLAnEZ45ZzGAhGtz1JGTHlx1rzCJZlZMuTNgLPx4iapPLQ5j7Z4t_-Ag3oZUCXZlAeE-ousIXxlYbUjmyl4WBQzP4q4P0lPMt_h7ClLMx-62_vIIuHl0U8AqeFwbRgvA"

	verifyBytes, err := ioutil.ReadFile("rsa_public.pem")

	if err != nil {
		panic("invalid key file")
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

	if err != nil {
		panic("invalid key format")
	}

	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return verifyKey, nil
	})

	_ = token

	if err != nil {
		panic("invalid token")
	}

	// fmt.Println(token.Header["alg"])
	// fmt.Println(token.Header["jti"])
	// fmt.Println(token.Header["typ"])

	// fmt.Println(token.Claims)

	// fmt.Println()

	// v := reflect.ValueOf(*token)

	// typeOfS := v.Type()

	// for i := 0; i < v.NumField(); i++ {
	// 	fmt.Printf("Field: %s\tValue: %v\n", typeOfS.Field(i).Name, v.Field(i).Interface())
	// }
}

func VerifyJose() {

	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjVlYTRiYmY4ZmEwOTgzOTg3ZDI5MmU2MjAzNzMwNjQ5Y2M1ZGE3ZGNmZmZmNDEwMDlhZjllMzNjY2UzMjU1NGEwN2I1MGRjOWVlMmUxYWJiIn0.eyJhdWQiOiIxIiwianRpIjoiNWVhNGJiZjhmYTA5ODM5ODdkMjkyZTYyMDM3MzA2NDljYzVkYTdkY2ZmZmY0MTAwOWFmOWUzM2NjZTMyNTU0YTA3YjUwZGM5ZWUyZTFhYmIiLCJpYXQiOjE1NjM2MzQ4NzksIm5iZiI6MTU2MzYzNDg3OSwiZXhwIjoxNTk1MjU3Mjc5LCJzdWIiOiI2NCIsInNjb3BlcyI6W119.oWFAa5gy1eB_HoNoGVUCDSoWWTceWdP-1UKJzn81Y4IQtKYUQuw37wm63VVSZsf7kz1K2r1T93k4oYijyMjHupj4LDaoO2pD0nlIorSoDwIYgF-MkFwSv0FacdECswYBLi_yUiBwaMF7k6QaI5BrCjsqFsqiYCM-7JPa5xdEmD3JXr5QQmizWHb6c6ggv7TNQCW_S8MlblTTbl4izINTfb7u2K8jgJ9cpeapAGmfAMHFamCSXEPOzpfiDxdAIXRT7f5w58yYsT2ng3YuTE_M6f4nuwTNxGN907N-x5JJbcLEuL3Tykd11F9fuU4AimacCsSf3M8L0e15gr8dmhaUy3the4uTKTmD8bFTtqYs87DT6guVokrnQNphhGDE2VT9dr6MyX0ap_RpWDcbkYDMzMfjLcWRcSywNKH93QAO5kquNLUyGiWa4r4uqbe7E6w6fESOoJGvTkWQ85-x6bl9aw_NgNz-UIa0TO-I1SNGvpckMnTekD5RMPquDrhXxGMpw_A-B5SXWcsRPMnS-dDH5DjDf1mRgsfNJg-iGYZ6Rk9PLAnEZ45ZzGAhGtz1JGTHlx1rzCJZlZMuTNgLPx4iapPLQ5j7Z4t_-Ag3oZUCXZlAeE-ousIXxlYbUjmyl4WBQzP4q4P0lPMt_h7ClLMx-62_vIIuHl0U8AqeFwbRgvA"

	keyBytes, err := ioutil.ReadFile("rsa_public.pem")

	if err != nil {
		panic("invalid key file")
	}

	publicKey, e := Rsa.ReadPublic(keyBytes)

	if e != nil {
		panic("invalid key format")
	}

	payload, headers, err := jose.Decode(token, publicKey)

	_ = headers
	_ = payload

	if err != nil {
		panic("invalid token")
	}

	// if err == nil {
	// 	//go use token
	// 	fmt.Printf("\npayload = %v\n", payload)

	// 	//and/or use headers
	// 	fmt.Printf("\nheaders = %v\n", headers)
	// }
}

func VerifyJwtWithToken() {

	var (
		verifyKey *rsa.PublicKey
	)

	tokenValue := SignJwt()

	verifyBytes, err := ioutil.ReadFile("rsa_public.pem")

	if err != nil {
		panic("invalid key file")
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

	if err != nil {
		panic("invalid key format")
	}

	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return verifyKey, nil
	})

	_ = token

	if err != nil {
		panic("invalid token")
	}

	// fmt.Println(token.Header["alg"])
	// fmt.Println(token.Header["jti"])
	// fmt.Println(token.Header["typ"])

	// fmt.Println(token.Claims)

	// fmt.Println()

	// v := reflect.ValueOf(*token)

	// typeOfS := v.Type()

	// for i := 0; i < v.NumField(); i++ {
	// 	fmt.Printf("Field: %s\tValue: %v\n", typeOfS.Field(i).Name, v.Field(i).Interface())
	// }
}

func VerifyJoseWithToken() {

	token := SignJose()

	keyBytes, err := ioutil.ReadFile("rsa_public.pem")

	if err != nil {
		panic("invalid key file")
	}

	publicKey, e := Rsa.ReadPublic(keyBytes)

	if e != nil {
		panic("invalid key format")
	}

	payload, headers, err := jose.Decode(token, publicKey)

	_ = headers
	_ = payload

	if err != nil {
		panic("invalid token")
	}

	// if err == nil {
	// 	//go use token
	// 	fmt.Printf("\npayload = %v\n", payload)

	// 	//and/or use headers
	// 	fmt.Printf("\nheaders = %v\n", headers)
	// }
}

func main() {
	fmt.Println("go test -bench=. -timeout=20m -benchtime=10s -benchmem")
	os.Exit(1)
}
