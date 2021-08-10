/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_B_VLAN_H_
#define NETLINK_B_VLAN_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>

#ifdef __cplusplus
extern "C" {
#endif
struct rtnl_bridge_vlan;
struct rtnl_vlan_port;

struct rtnl_bridge_vlan *rtnl_bridge_vlan_alloc(void);
struct rtnl_bridge_vlan *rtnl_bridge_vlan_get(struct nl_cache *cache,
					      int ifindex, int vlan);
void rtnl_bridge_vlan_put(struct rtnl_bridge_vlan *bvlan);
int rtnl_bridge_vlan_alloc_cache(struct nl_sock *sk,
				 struct nl_cache **result);
int rtnl_bridge_vlan_alloc_cache_flags(struct nl_sock *sock,
				       struct nl_cache **result,
				       unsigned int flags);
int rtnl_bridge_vlan_change(struct nl_sock *sk,
			    struct rtnl_bridge_vlan *orig,
			    struct rtnl_bridge_vlan *changes,
			    int flags);
int rtnl_bridge_vlan_build_change_request(struct rtnl_bridge_vlan *orig, struct rtnl_bridge_vlan
					  *changes, int flags,
					  struct nl_msg **result);
int rtnl_bridge_vlan_get_ifindex(struct rtnl_bridge_vlan *bvlan);
int rtnl_bridge_vlan_set_ifindex(struct rtnl_bridge_vlan *bvlan,
				 int ifindex);

int rtnl_bridge_vlan_get_vlan_id(struct rtnl_bridge_vlan *bvlan);
int rtnl_bridge_vlan_set_vlan_id(struct rtnl_bridge_vlan *bvlan,
				       uint16_t vid);

extern struct rtnl_vlan_port * rtnl_bridge_vp_alloc(void);
extern struct rtnl_vlan_port * rtnl_bridge_vp_clone(struct rtnl_vlan_port *);
extern void rtnl_bridge_vp_free(struct rtnl_vlan_port *);

extern void	rtnl_bridge_vlan_add_port(struct rtnl_bridge_vlan *,
				       struct rtnl_vlan_port *);
extern void	rtnl_bridge_vlan_remove_port(struct rtnl_bridge_vlan *,
					  struct rtnl_vlan_port *);

extern int	rtnl_bridge_vlan_get_nports(struct rtnl_bridge_vlan *);
extern struct rtnl_vlan_port *rtnl_bridge_vlan_port_n(struct rtnl_bridge_vlan *bv, int n);

int rtnl_bridge_vp_get_ifindex(struct rtnl_vlan_port *bvlan, uint32_t *ifindex);
int rtnl_bridge_vp_set_ifindex(struct rtnl_vlan_port *bvlan, uint32_t ifindex);
int rtnl_bridge_vp_get_state(struct rtnl_vlan_port *bv, uint8_t *state);
int rtnl_bridge_vp_set_state(struct rtnl_vlan_port *vp, uint8_t state);

#ifdef __cplusplus
}
#endif
#endif
