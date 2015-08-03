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
		assert.False(VerifyExp(0, exp), "False if now == exp")
	}
	{
		exp := now.Add(time.Second).Unix()
		assert.True(VerifyExp(0, exp), "True if now < exp")
	}
	{
		skew := time.Second
		assert.True(VerifyExp(skew, now.Unix()), "True if now == exp + 1s")
	}
}
