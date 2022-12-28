package sso

import (
	"net/url"
	"strings"

	"github.com/sbasestarter/bizuserlib"
)

func NewCfgSSO(whileSSOJumpDomains []string) bizuserlib.SSO {
	m := make(map[string]interface{})

	for _, domain := range whileSSOJumpDomains {
		m[strings.ToLower(domain)] = true
	}

	return &cfgSSOImpl{whileSSOJumpDomainsMap: m}
}

type cfgSSOImpl struct {
	whileSSOJumpDomainsMap map[string]interface{}
}

func (impl *cfgSSOImpl) CheckJumpURL(ssoJumpURL string) (valid bool) {
	if ssoJumpURL == "" {
		return
	}

	u, err := url.Parse(ssoJumpURL)
	if err != nil {
		return
	}

	if u == nil || u.Host == "" {
		return
	}

	host := strings.ToLower(u.Host)

	if _, ok := impl.whileSSOJumpDomainsMap[host]; !ok {
		for match := range impl.whileSSOJumpDomainsMap {
			if strings.HasSuffix(host, match) {
				valid = true

				break
			}
		}
	} else {
		valid = true
	}

	return
}
