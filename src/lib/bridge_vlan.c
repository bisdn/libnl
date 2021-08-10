/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * src/lib/bridge_vlan.c     CLI Link Helpers
 *
 */

/**
 * @ingroup cli
 * @defgroup cli_bridge_vlan Bridge Vlan
 *
 * @{
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/bridge_vlan.h>
#include <linux/if_bridge.h>
#include <netlink/route/bridge_vlan.h>

struct rtnl_bridge_vlan *nl_cli_bridge_vlan_alloc(void)
{
	struct rtnl_bridge_vlan *bvlan;

	bvlan = rtnl_bridge_vlan_alloc();
	if (!bvlan)
		nl_cli_fatal(ENOMEM, "Unable to allocate bridge-vlan object");

	return bvlan;
}

struct nl_cache *nl_cli_bridge_vlan_alloc_cache_flags(struct nl_sock *sock,
						unsigned int flags)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_bridge_vlan_alloc_cache_flags(sock, &cache, flags)) < 0)
		nl_cli_fatal(err, "Unable to allocate route cache: %s\n",
			     nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

void nl_cli_bridge_vlan_parse_ifindex(struct rtnl_bridge_vlan *bvlan, int ifindex)
{
	rtnl_bridge_vlan_set_ifindex(bvlan, ifindex);
}
