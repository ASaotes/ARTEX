package server

import "testing"

// testAuthToken signs a token for the password hash the test server currently
// has. Tokens are bound to that version (see authPasswordVersion), so a fixed
// helper signing with an empty hash would break as soon as the shared dev DB
// has an admin password configured.
func testAuthToken(t *testing.T, s *Server) (string, error) {
	t.Helper()
	hash := ""
	if s.m != nil && s.m.pg != nil {
		h, _, err := s.m.pg.GetSetting(authPassKey)
		if err != nil {
			return "", err
		}
		hash = h
	}
	return signJWTForHash(s.jwtKey, hash)
}
