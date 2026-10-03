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

type roleHandler struct {
	accessManager cloudaccess.AccessManager
	roleManager   cloudaccess.RoleManager
}

func registerRoleEndpoints(accessManager cloudaccess.AccessManager, roleManager cloudaccess.RoleManager, router *mux.Router) {
	rh := &roleHandler{accessManager: accessManager, roleManager: roleManager}
	router.HandleFunc("/cloud-roles", rh.getAllRolesInAccount).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles", rh.getAllRolesInAccess).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles", rh.createRole).Methods("POST", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}", rh.getRole).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}", rh.updateRole).Methods("PUT", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}", rh.deleteRole).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}/validate", rh.validateRole).Methods("POST", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}/aws-deploy-script", rh.getAWSDeployScript).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}/gcp-deploy-script", rh.getGCPDeployScript).Methods("GET", "OPTIONS")
	router.HandleFunc("/cloud-access/{cloudAccessId}/roles/{cloudRoleId}/azure-deploy-script", rh.getAzureDeployScript).Methods("GET", "OPTIONS")
}

func (h *roleHandler) getAllRolesInAccount(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	roles, err := h.roleManager.GetAllRolesInAccount(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	access, err := h.accessManager.GetAllCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accessByID := make(map[string]*types.CloudAccess, len(access))
	for _, a := range access {
		accessByID[a.ID] = a
	}

	out := make([]*api.CloudRole, 0, len(roles))
	for _, role := range roles {
		parent, ok := accessByID[role.CloudAccessID]
		if !ok {
			continue
		}
		out = append(out, role.ToAPIResponse(parent.ProviderAccountID, parent.Provider))
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *roleHandler) getAllRolesInAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	access, err := h.accessManager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	roles, err := h.roleManager.GetAllRolesInAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.CloudRole, 0, len(roles))
	for _, role := range roles {
		out = append(out, role.ToAPIResponse(access.ProviderAccountID, access.Provider))
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *roleHandler) createRole(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]

	var req api.CloudRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	role := types.NewCloudRole(userAuth.AccountId, cloudAccessID)
	role.FromAPIRequest(&req)

	created, err := h.roleManager.CreateRole(r.Context(), userAuth.UserId, role)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	access, err := h.accessManager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse(access.ProviderAccountID, access.Provider))
}

func (h *roleHandler) getRole(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]

	access, err := h.accessManager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	role, err := h.roleManager.GetRole(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, role.ToAPIResponse(access.ProviderAccountID, access.Provider))
}

func (h *roleHandler) updateRole(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]
	if roleID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "cloud role ID is required"), w)
		return
	}

	var req api.CloudRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	role := &types.CloudRole{ID: roleID, AccountID: userAuth.AccountId, CloudAccessID: cloudAccessID}
	role.FromAPIRequest(&req)

	updated, err := h.roleManager.UpdateRole(r.Context(), userAuth.UserId, role)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	access, err := h.accessManager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse(access.ProviderAccountID, access.Provider))
}

func (h *roleHandler) deleteRole(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]
	if err := h.roleManager.DeleteRole(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *roleHandler) validateRole(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]

	updated, err := h.roleManager.ValidateRole(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	access, err := h.accessManager.GetCloudAccess(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse(access.ProviderAccountID, access.Provider))
}

// getAWSDeployScript renders the AWS setup script. mode is an optional - default is "create"
func (h *roleHandler) getAWSDeployScript(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]
	mode := r.URL.Query().Get("mode")

	steps, err := h.roleManager.GetAWSDeployScript(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID, mode)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, api.CloudDeployStepsResponse{
		Steps: toAPICloudDeploySteps(steps.Steps),
	})
}

// getGCPDeployScript renders the GCP setup script. mode is an optional - default is "create"
func (h *roleHandler) getGCPDeployScript(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]
	mode := r.URL.Query().Get("mode")

	steps, err := h.roleManager.GetGCPDeployScript(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID, mode)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, api.CloudDeployStepsResponse{
		Steps: toAPICloudDeploySteps(steps.Steps),
	})
}

// getAzureDeployScript renders the Azure setup script. mode is an optional - default is "create"
func (h *roleHandler) getAzureDeployScript(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cloudAccessID := mux.Vars(r)["cloudAccessId"]
	roleID := mux.Vars(r)["cloudRoleId"]
	mode := r.URL.Query().Get("mode")

	steps, err := h.roleManager.GetAzureDeployScript(r.Context(), userAuth.AccountId, userAuth.UserId, cloudAccessID, roleID, mode)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, api.CloudDeployStepsResponse{
		Steps: toAPICloudDeploySteps(steps.Steps),
	})
}

// toAPICloudDeploySteps converts cloudaccess.CloudDeployStep to the deploy steps
func toAPICloudDeploySteps(steps []cloudaccess.CloudDeployStep) []api.CloudDeployStep {
	out := make([]api.CloudDeployStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, api.CloudDeployStep{
			Title:       s.Title,
			Description: s.Description,
			Command:     s.Command,
		})
	}
	return out
}
