package jwt

import "time"

// VerifyExp verifies exp (expiration time). It will return true if
// the current time is before exp. Otherwise, it will return false.
// See http://openid.net/specs/openid-connect-core-1_0.html#IDToken
func VerifyExp(skew time.Duration, exp int64) bool {
	return verifyExp(time.Now(), skew, exp)
}

func verifyExp(now time.Time, skew time.Duration, exp int64) bool {
	expT := time.Unix(exp, 0)
	skewT := expT.Add(skew)
	return now.Before(skewT)
}
