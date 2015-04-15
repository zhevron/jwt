jwt - JSON Web Token library
============================

[![Coverage Status](https://img.shields.io/coveralls/zhevron/jwt.svg)](https://coveralls.io/r/zhevron/jwt)
[![Build Status](https://travis-ci.org/zhevron/jwt.svg?branch=master)](https://travis-ci.org/zhevron/jwt)
[![GoDoc](https://godoc.org/github.com/zhevron/jwt?status.svg)](https://godoc.org/github.com/zhevron/jwt)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/zhevron/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

**jwt** is a simple library for handling [JSON Web Tokens](http://jwt.io/) in [Go](https://golang.org/).  
The library is developed based on [draft-ietf-oauth-json-web-token-32](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32).

## Installation

You can install the library using the standard `go get` command:

```
go get gopkg.in/zhevron/jwt.v1
```

**Note:** This package requires Go 1.3 or higher.

## Examples

### JSON Web Token (HMAC, HS256)
```go
import (
  "fmt"

  "gopkg.in/zhevron/jwt.v1"
)

func main() {
  key := "secret"

  token := jwt.NewToken()
  token.Claims["username"] = "my_username"

  tokenstring, err := token.Sign(key)
  if err != nil {
    panic(err)
  }

  token, err = jwt.DecodeToken(tokenstring, jwt.HS256, key)
  if err != nil {
    panic(err)
  }

  fmt.Printf("Your username is: %s\n", token.Claims["username"])
}
```

### JSON Web Token (RSA, RS256)
```go
import (
  "fmt"

  "gopkg.in/zhevron/jwt.v1"
)

func main() {
  privateKey = `-----BEGIN RSA PRIVATE KEY-----
myprivatekeyhere
-----END RSA PRIVATE KEY-----`
  publicKey = `-----BEGIN PUBLIC KEY-----
mypublickeyhere  
-----END PUBLIC KEY-----`

  token := jwt.NewToken()
  token.Algorithm = jwt.RS256
  token.Claims["username"] = "my_username"

  tokenstring, err := token.Sign(privateKey)
  if err != nil {
    panic(err)
  }

  token, err = jwt.DecodeToken(tokenstring, jwt.RS256, publicKey)
  if err != nil {
    panic(err)
  }

  fmt.Printf("Your username is: %s\n", token.Claims["username"])
}
```

### JSON Web Token (ECDSA, ES256)
```go
import (
  "fmt"

  "gopkg.in/zhevron/jwt.v1"
)

func main() {
  privateKey = `-----BEGIN EC PRIVATE KEY-----
myprivatekeyhere
-----END EC PRIVATE KEY-----`
  publicKey = `-----BEGIN PUBLIC KEY-----
mypublickeyhere  
-----END PUBLIC KEY-----`

  token := jwt.NewToken()
  token.Algorithm = jwt.ES256
  token.Claims["username"] = "my_username"

  tokenstring, err := token.Sign(privateKey)
  if err != nil {
    panic(err)
  }

  token, err = jwt.DecodeToken(tokenstring, jwt.ES256, publicKey)
  if err != nil {
    panic(err)
  }

  fmt.Printf("Your username is: %s\n", token.Claims["username"])
}
```

## License

**jwt** is licensed under the [MIT license](http://opensource.org/licenses/MIT).
