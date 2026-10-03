package cloudfederation

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/federation/.well-known/openid-configuration", i.handleOpenIDConfiguration)
	mux.HandleFunc("/federation/keys", i.handleJWKS)
	return mux
}

func (i *Issuer) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(i.GetOpenIDConfiguration()); err != nil {
		log.WithContext(r.Context()).Errorf("failed to encode federation OpenID configuration: %v", err)
	}
}

func (i *Issuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := i.GetJWKS(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to build federation JWKS: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.WithContext(r.Context()).Errorf("failed to encode federation JWKS: %v", err)
	}
}
