package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVerifyExp(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()

	{
		exp := now.Unix()
		assert.False(verifyExp(now, 0, exp), "False if now == exp")
	}
	{
		exp := now.Add(time.Second).Unix()
		assert.True(verifyExp(now, 0, exp), "True if now < exp")
	}
	{
		skew := time.Second
		assert.True(verifyExp(now, skew, now.Unix()), "True if now == exp + 1s")
	}
}
