package daemon

import "log"

// sendHeartbeat POSTs a heartbeat to the portal.
func (d *Daemon) sendHeartbeat() {
	if d.apiClient == nil {
		return
	}
	_, err := d.apiClient.SendHeartbeat()
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}
	log.Println("Heartbeat sent to portal")
}
