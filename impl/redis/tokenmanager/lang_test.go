package tokenmanager

import (
	"encoding/json"
	"testing"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/stretchr/testify/assert"
)

func TestEnum(t *testing.T) {
	s := string(bizuserinters.AuthenticatorAnonymous)
	a := bizuserinters.AuthenticatorIdentity(s)
	t.Log(a)

	s = "haha"
	a = bizuserinters.AuthenticatorIdentity(s)
	t.Log(s, a)
}

func TestM(t *testing.T) {
	m := make(map[string]interface{})
	m["1"] = 1
	d, err := json.Marshal(m)
	assert.Nil(t, err)

	var m2 map[string]interface{}
	err = json.Unmarshal(d, &m2)
	assert.Nil(t, err)
	assert.EqualValues(t, 1, len(m2))
	assert.EqualValues(t, 1, m2["1"])
}
