/*
 * netlink/cli/link.h     CLI Link Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008-2010 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __NETLINK_CLI_BVLAN_H_
#define __NETLINK_CLI_BVLAN_H_

#include <netlink/route/link.h>
#include <netlink/cli/utils.h>

extern struct rtnl_bridge_vlan *nl_cli_bridge_vlan_alloc(void);
extern struct nl_cache *nl_cli_bridge_vlan_alloc_cache_flags(struct nl_sock *sock,
						unsigned int flags);
void nl_cli_bridge_vlan_parse_ifindex(struct rtnl_bridge_vlan *bvlan, int ifindex);

#endif
