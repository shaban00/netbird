package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess"
	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type accessHandler struct {
	manager cloudaccess.AccessManager
}

func RegisterEndpoints(accessManager cloudaccess.AccessManager, roleManager cloudaccess.RoleManager, router *mux.Router) {
	ah := &accessHandler{manager: accessManager}
	router.HandleFunc("/cloud-access", ah.getAllCloudAccess).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access", ah.createCloudAccess).Methods("POST", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}", ah.getCloudAccess).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}", ah.updateCloudAccess).Methods("PUT", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}", ah.deleteCloudAccess).Methods("DELETE", "OPTIONS")

	registerRoleEndpoints(accessManager, roleManager, router)
}

func (h *accessHandler) getAllCloudAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	access, err := h.manager.GetAllCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.CloudAccess, 0, len(access))
	for _, a := range access {
		out = append(out, a.ToAPIResponse(a.Status))
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *accessHandler) createCloudAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.CloudAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	access := types.NewCloudAccess(userAuth.AccountId)
	access.FromAPIRequest(&req)

	created, err := h.manager.CreateCloudAccess(r.Context(), userAuth.UserId, access)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse(created.Status))
}

func (h *accessHandler) getCloudAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	id := mux.Vars(r)["cloudAccessId"]
	access, err := h.manager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, access.ToAPIResponse(access.Status))
}

func (h *accessHandler) updateCloudAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	id := mux.Vars(r)["cloudAccessId"]
	if id == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "cloud access ID is required"), w)
		return
	}

	var req api.CloudAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	access := &types.CloudAccess{ID: id, AccountID: userAuth.AccountId}
	access.FromAPIRequest(&req)

	updated, err := h.manager.UpdateCloudAccess(r.Context(), userAuth.UserId, access)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse(updated.Status))
}

func (h *accessHandler) deleteCloudAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	id := mux.Vars(r)["cloudAccessId"]
	if err := h.manager.DeleteCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, id); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
