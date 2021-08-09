#include "wireguardif.h"
#include "wireguard.h"

#define LOCAL_ADDRESS		IPADDR4_INIT_BYTES(10, 0, 2, 2)
#define LOCAL_NETMASK		IPADDR4_INIT_BYTES(255, 255, 255, 0)
#define GATEWAY_ADDRESS		IPADDR4_INIT_BYTES(10, 0, 2, 1)

#define CLIENT_PRIVATE_KEY	"XXX"
#define CLIENT_PORT			51820

#define PEER_PUBLIC_KEY		"YYY"
#define PEER_PORT			55820
#define PEER_ADDRESS		IPADDR4_INIT_BYTES(192, 168, 0, 5)


static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index_local = WIREGUARDIF_INVALID_INDEX;

void wireguard_setup() {
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	ip_addr_t ipaddr = LOCAL_ADDRESS;
	ip_addr_t netmask = LOCAL_NETMASK;
	ip_addr_t gateway = GATEWAY_ADDRESS;

	// Setup the WireGuard device structure
	wg.private_key = CLIENT_PRIVATE_KEY;
	wg.listen_port = CLIENT_PORT;
	wg.bind_netif = NULL;	// NB! not working on ESP32 even if set!

	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(wg_netif);

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(&peer);
	peer.public_key = PEER_PUBLIC_KEY;
	peer.preshared_key = NULL;
	// Allow all IPs through tunnel
	//peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    IP_ADDR4(&peer.allowed_ip, 0, 0, 0, 0);
	IP_ADDR4(&peer.allowed_mask, 0, 0, 0, 0);

	// If we know the endpoint's address can add here
	IP_ADDR4(&peer.endpoint_ip, PEER_ADDRESS);
	peer.endport_port = PEER_PORT;

	// Register the new WireGuard peer with the netwok interface
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index_local);

	if ((wireguard_peer_index_local != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
		// Start outbound connection to peer
		wireguardif_connect(wg_netif, wireguard_peer_index_local);
	}
}