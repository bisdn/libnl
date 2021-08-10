/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * src/nl-bridge.c     Bridge utility
 */

#include "nl-default.h"

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/bridge_vlan.h>
#include <netlink/cli/link.h>

#include <linux/netlink.h>

int main(int argc, char *argv[])
{
	struct nl_cache *bvlan_cache, *link_cache;
	struct nl_sock *sock;
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_DETAILS,
		.dp_fd = stdout,
	};

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_ROUTE);
	link_cache = nl_cli_link_alloc_cache_flags(sock, NL_CACHE_AF_ITER);
	bvlan_cache = nl_cli_bridge_vlan_alloc_cache_flags(sock, NL_CACHE_AF_ITER);

	nl_cache_dump(bvlan_cache, &dp);

	printf("end\n");

	return 0;
}
