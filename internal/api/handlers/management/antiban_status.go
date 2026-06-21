package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// GetAntiBanEgressStatus returns the latest egress IP self-check snapshot: for
// each Claude credential, its current egress IP, country, ISP, datacenter verdict,
// and whether it is currently held out of rotation. Read-only; returns an empty
// list when the self-check has not run or is disabled.
func (h *Handler) GetAntiBanEgressStatus(c *gin.Context) {
	status := coreauth.GetEgressStatus()
	if status == nil {
		status = []coreauth.EgressStatus{}
	}
	c.JSON(http.StatusOK, gin.H{"egress-status": status})
}
