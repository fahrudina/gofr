package encb64

import (
    "crypto/hmac"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
    "time"
)

func Validate_Password(hashed string, input_password string) bool {
    salt := hashed[0:8]
    if hashed == Encrypt_Password(input_password, []byte(salt)) {
        return true
    } else {
        return false
    }
    return false
}

func Encrypt_Password(password string, salt []byte) string {
    if salt == nil {
        m := md5.New()
        m.Write([]byte(time.Now().String()))
        s := hex.EncodeToString(m.Sum(nil))
        salt = []byte(s[2:10])
    }
    mac := hmac.New(sha256.New, salt)
    mac.Write([]byte(password))
    s := hex.EncodeToString(mac.Sum(nil))

    hasher := sha1.New()
    hasher.Write([]byte(s))

    result := hex.EncodeToString(hasher.Sum(nil))

    p := string(salt) + result

    return p
}