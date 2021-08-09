//==============================================================================
// Wireguard VPN Client demo for LwIP/ESP32     
//==============================================================================

//==============================================================================
//  Includes
//==============================================================================
#include "wireguardif.h"
#include "wireguard.h"

#include "wireguard_vpn.h"

//==============================================================================
//  Defines
//==============================================================================
#define CMP_NAME "WG_VPN"

#if !defined(WG_CLIENT_PRIVATE_KEY) || !defined(WG_PEER_PUBLIC_KEY)
#error "Please update configuratiuon with your VPN-specific keys!"
#endif

//==============================================================================
//  Local types
//==============================================================================

//==============================================================================
//  Local data
//==============================================================================
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index_local = WIREGUARDIF_INVALID_INDEX;

//==============================================================================
//  Exported data
//==============================================================================

//==============================================================================
//  Local functions
//==============================================================================

//==============================================================================
//  Exported functions
//==============================================================================
void wireguard_setup()
{
    struct wireguardif_init_data wg;
    struct wireguardif_peer peer;
    const ip_addr_t ipaddr = WG_LOCAL_ADDRESS;
    const ip_addr_t netmask = WG_LOCAL_NETMASK;
    const ip_addr_t gateway = WG_GATEWAY_ADDRESS;
    const ip_addr_t peer_address = WG_PEER_ADDRESS;

    // Setup the WireGuard device structure
    wg.private_key = WG_CLIENT_PRIVATE_KEY;
    wg.listen_port = WG_CLIENT_PORT;
    wg.bind_netif = NULL; // NB! not working on ESP32 even if set!

    // Register the new WireGuard network interface with lwIP
    wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);

    // Mark the interface as administratively up, link up flag is set automatically when peer connects
    netif_set_up(wg_netif);

    // Initialise the first WireGuard peer structure
    wireguardif_peer_init(&peer);
    peer.public_key = WG_PEER_PUBLIC_KEY;
    peer.preshared_key = NULL;
    // Allow all IPs through tunnel
    //peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    IP_ADDR4(&peer.allowed_ip, 0, 0, 0, 0);
    IP_ADDR4(&peer.allowed_mask, 0, 0, 0, 0);

    // If we know the endpoint's address can add here
    ip_addr_set(&peer.endpoint_ip, &peer_address);
    peer.endport_port = WG_PEER_PORT;

    // Register the new WireGuard peer with the netwok interface
    wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index_local);

    if ((wireguard_peer_index_local != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip))
    {
        // Start outbound connection to peer
        wireguardif_connect(wg_netif, wireguard_peer_index_local);
    }
}