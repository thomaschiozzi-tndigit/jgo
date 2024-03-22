package jwt

import "testing"

func TestVerifySignature(t *testing.T) {

	//mockIss := "http://localhost:"
	//oidcDiscovery := `{"jwks_uri"}`
	// this tests requires an online party, hence is not very reliable
	// moreover the key might contain sensible data
	jws := "eyJraWQiOiIxMzE4Njg1Zi00ZDc2LTRlOTYtYjZiMS1lNjIwYjQwYTEyYTYiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoibHQtU0Z2RTlSbDJBejctc2tRczBzUSIsInN1YiI6InVfODFkZDFhNTQ4ZDRiNDE0OTllOGQ4MThlNGI2YmFiNmMiLCJhdWQiOiJjX2UzOGMwMDgzMTQxMDRkMzNhOGFkYWRhMmI0N2NkMjQ5IiwibmJmIjoxNzExMDQ2NjMwLCJhenAiOiJjX2UzOGMwMDgzMTQxMDRkMzNhOGFkYWRhMmI0N2NkMjQ5IiwiYXV0aF90aW1lIjoxNzExMDQ2NTUxLCJpc3MiOiJodHRwczpcL1wvYWFjLWRldi5jbG91ZC10ZXN0LnRuZGlnaXQuaXQiLCJleHAiOjE3MTEwNTAyMzAsImlhdCI6MTcxMTA0NjYzMCwianRpIjoiTVl1SVRtRWVFT2thR3BTMzd6RFV4VjE1V000In0.B76mJjaZNualNaGAK_hgoetki4KfTr0hVfm17_2574ddu5yBKKFI60szLMEQCjxm-qm1f6W4sJUgRFOYR5swe8MY_hj3YeQgSje_XyUJS557IoVCpJ6S1gcnwb5CrzZcA9mrjc910JYgzntcAWHbSdrrcddaenZ3pX7q2V5sLmwssTblo9AMGuoLyQBDhiSY0p4p-3KBBo3jYHOKzEyQgwswYZwpv3gB2B0bapqAREiPfxbjWmGg-T8SBCl3Pr9aEqypTSyxfekrfk25kd7_ovBteuRPEyli1QHPgViCgf4Ww-Ns2Nch36g_I6aNp7UIQ483cgTI7ie3Ub5lANUxRQ"
	ok, err := VerifySignature(jws)
	if !ok && err != nil {
		t.Fatal(err)
	}
}
