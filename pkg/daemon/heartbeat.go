package daemon

import "log"

// sendHeartbeat POSTs a heartbeat to the portal.
func (d *Daemon) sendHeartbeat() {
	if d.apiClient == nil {
		return
	}
	err := d.withReauth(func() error {
		_, callErr := d.apiClient.SendHeartbeat()
		return callErr
	})
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}
	log.Println("Heartbeat sent to portal")
}
