/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * lib/route/bridge_vlan.c		Bridge VLAN database
 */

#include "nl-default.h"

#include <netlink/route/link.h>
#include <netlink/route/bridge_vlan.h>
#include <netlink/netlink.h>
#include <linux/if_bridge.h>
#include <netlink/utils.h>

#include "nl-aux-core/nl-core.h"
#include "nl-priv-dynamic-core/nl-core.h"
#include "nl-priv-dynamic-core/object-api.h"
#include "nl-priv-dynamic-core/cache-api.h"

/** @cond SKIP */
#define BRIDGE_VLAN_ATTR_IFINDEX         0x000001
#define BRIDGE_VLAN_ATTR_FAMILY          0x000002
#define BRIDGE_VLAN_ATTR_VID             0x000004
#define BRIDGE_VLAN_ATTR_STATE           0x000008

static struct nl_cache_ops bridge_vlan_ops;
static struct nl_object_ops bridge_vlan_obj_ops;
/** @endcond */

struct rtnl_bridge_vlan {
	NLHDR_COMMON
	int32_t bv_ifindex;
	uint8_t family;

	uint16_t vlan_id;
	uint16_t msti;
	unsigned int bv_nr_ports;
	struct nl_list_head bv_ports;
};

struct rtnl_vlan_port {
	struct nl_list_head bvp_list;

	int32_t bvp_ifindex;
	uint8_t bvp_state;

	uint32_t ce_mask;
};

struct rtnl_vlan_port *rtnl_bridge_vp_alloc(void)
{
	struct rtnl_vlan_port *vp;

	vp = calloc(1, sizeof(*vp));
	if (!vp)
		return NULL;

	nl_init_list_head(&vp->bvp_list);

	return vp;
}

struct rtnl_vlan_port *rtnl_bridge_vp_clone(struct rtnl_vlan_port *src)
{
	struct rtnl_vlan_port *vp;

	vp = rtnl_bridge_vp_alloc();
	if (!vp)
		return NULL;

	vp->ce_mask = src->ce_mask;
	vp->bvp_ifindex = src->bvp_ifindex;
	vp->bvp_state = src->bvp_state;

	return vp;
}

void rtnl_bridge_vp_free(struct rtnl_vlan_port *vp)
{
	free(vp);
}

void rtnl_bridge_vlan_add_port(struct rtnl_bridge_vlan *bv, struct rtnl_vlan_port *vp)
{
	nl_list_add_tail(&vp->bvp_list, &bv->bv_ports);
	bv->bv_nr_ports++;
}

void rtnl_bridge_vlan_remove_port(struct rtnl_bridge_vlan *bv, struct rtnl_vlan_port *vp)
{
	bv->bv_nr_ports--;
	nl_list_del(&vp->bvp_list);
}

int rtnl_bridge_vlan_get_nports(struct rtnl_bridge_vlan *bv)
{
	return bv->bv_nr_ports;
}

struct rtnl_vlan_port *rtnl_bridge_vlan_port_n(struct rtnl_bridge_vlan *bv, int n)
{
	struct rtnl_vlan_port *vp;

	if (n >= 0 && ((unsigned)n) < bv->bv_nr_ports) {
		int i;

		i = 0;
		nl_list_for_each_entry(vp, &bv->bv_ports, bvp_list) {
			if (i == n) return vp;
			i++;
		}
	}
	return NULL;
}

static uint64_t bridge_vlan_compare(struct nl_object *_a, struct nl_object *_b,
				    uint64_t attrs, int flags)
{
	struct rtnl_bridge_vlan *a = (struct rtnl_bridge_vlan *) _a;
	struct rtnl_bridge_vlan *b = (struct rtnl_bridge_vlan *) _b;
	uint64_t diff = 0;

#define BRIDGE_VLAN_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, BRIDGE_VLAN_ATTR_##ATTR, a, b, EXPR)

	diff |= BRIDGE_VLAN_DIFF(IFINDEX, a->bv_ifindex != b->bv_ifindex);
	diff |= BRIDGE_VLAN_DIFF(FAMILY, a->family != b->family);
	diff |= BRIDGE_VLAN_DIFF(VID, a->vlan_id != b->vlan_id);
	//diff |= BRIDGE_VLAN_DIFF(STATE, a->state != b->state);

#undef BRIDGE_VLAN_DIFF

	return diff;
}

static void br_vlan_dump_line(struct nl_object *_obj, struct nl_dump_params *p)
{
	struct rtnl_bridge_vlan *obj = (struct rtnl_bridge_vlan *) _obj;
	unsigned int i;

	nl_dump(p, "bridge=%d", obj->bv_ifindex);
	nl_dump(p, " VLAN=%d MSTI=%d ports=", obj->vlan_id, obj->msti);
	for (i = 0; i < obj->bv_nr_ports; i++) {
		struct rtnl_vlan_port *vp = rtnl_bridge_vlan_port_n(obj, i);

		if (i > 0)
			nl_dump(p,",");
		nl_dump(p, "<Ifindex=%i,State=%d>",  vp->bvp_ifindex, vp->bvp_state);
	}
	nl_dump(p, "\n");
}

static int bridge_vlan_request_update_type(struct nl_cache *cache,
				      struct nl_sock *sk,
				      uint32_t flags)
{
	_nl_auto_nl_msg struct nl_msg *msg = NULL;
	struct br_vlan_msg bvm = {
		.family = PF_BRIDGE,
	};
	uint32_t dump_flags = flags;
	int err;

	msg = nlmsg_alloc_simple(RTM_GETVLAN, NLM_F_DUMP);
	if (!msg)
		return -NLE_NOMEM;
	if (nlmsg_append(msg, &bvm, sizeof(bvm), NLMSG_ALIGNTO) < 0)
		return -NLE_MSGSIZE;

	if (dump_flags) {
		err = nla_put(msg, BRIDGE_VLANDB_DUMP_FLAGS, sizeof(dump_flags), &dump_flags);
		if (err < 0)
			return err;
	}

	err = nl_send_auto_complete(sk, msg);

	return err >= 0 ? 0 : err;
}

static int next_dump;

static int bridge_vlan_request_update(struct nl_cache *cache,
				      struct nl_sock *sk)
{
	int err;

	next_dump ^= BRIDGE_VLANDB_DUMPF_GLOBAL;

	err = bridge_vlan_request_update_type(cache, sk, next_dump);

	return err >= 0 ? 0 : err;
}

static struct nla_policy br_vlandb_policy[BRIDGE_VLANDB_MAX + 1] = {
	[BRIDGE_VLANDB_ENTRY] = {.type = NLA_NESTED},
};

static struct nla_policy br_vlandb_entry_policy[BRIDGE_VLANDB_ENTRY_MAX + 1] = {
	[BRIDGE_VLANDB_ENTRY_INFO] = {.type = NLA_BINARY,
				      .minlen = sizeof(struct bridge_vlan_info),
				      .maxlen =
				      sizeof(struct bridge_vlan_info)},
	[BRIDGE_VLANDB_ENTRY_RANGE] = {.type = NLA_U16},
	[BRIDGE_VLANDB_ENTRY_STATE] = {.type = NLA_U8},
	[BRIDGE_VLANDB_ENTRY_TUNNEL_INFO] = {.type = NLA_NESTED},
};

static struct nla_policy br_vlandb_gopts_policy[BRIDGE_VLANDB_GOPTS_MAX + 1] = {
	[BRIDGE_VLANDB_GOPTS_ID] = {.type = NLA_U16},
	[BRIDGE_VLANDB_GOPTS_RANGE] = {.type = NLA_U16},
	[BRIDGE_VLANDB_GOPTS_MSTI] = {.type = NLA_U16},
};

static int bridge_vlan_parse_entry(struct nl_cache_ops *ops, struct nlmsghdr *nlh,
				struct nlattr *entry, struct br_vlan_msg *bmsg,
				uint32_t br_ifindex, struct nl_parser_param *pp)
{
	struct bridge_vlan_info *bvlan_info = NULL;
	struct nlattr *tb[BRIDGE_VLANDB_ENTRY_MAX + 1];
	uint16_t range = 0;
	uint8_t state = 0;
	unsigned int i;
	int err;

	nla_parse_nested(tb, BRIDGE_VLANDB_ENTRY_MAX, entry,
			 br_vlandb_entry_policy);

	if (tb[BRIDGE_VLANDB_ENTRY_INFO])
		bvlan_info = nla_data(tb[BRIDGE_VLANDB_ENTRY_INFO]);

	if (tb[BRIDGE_VLANDB_ENTRY_STATE])
		state = nla_get_u8(tb[BRIDGE_VLANDB_ENTRY_STATE]);

	if (tb[BRIDGE_VLANDB_ENTRY_RANGE])
		range = nla_get_u16(tb[BRIDGE_VLANDB_ENTRY_RANGE]);
	else
		range = bvlan_info->vid;

	if (!bvlan_info)
		return -EINVAL;

	for (i = bvlan_info->vid; i <= range; i++) {
		struct rtnl_bridge_vlan *bvlan = rtnl_bridge_vlan_alloc();
		struct rtnl_vlan_port *port;

		if (!bvlan)
			return -ENOMEM;

		port = rtnl_bridge_vp_alloc();
		if (!port) {
			rtnl_bridge_vlan_put(bvlan);
			return -ENOMEM;
		}

		bvlan->ce_msgtype = nlh->nlmsg_type;
		bvlan->bv_ifindex = br_ifindex;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_IFINDEX;
		bvlan->family = bmsg->family;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_FAMILY;
		bvlan->vlan_id = i;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_VID;

		port->bvp_ifindex = bmsg->ifindex;
		port->bvp_state = state;
		port->ce_mask |= BRIDGE_VLAN_ATTR_STATE;
		rtnl_bridge_vlan_add_port(bvlan, port);

		NL_DBG(2, "br=%i port=%i vid=%i.\n", br_ifindex, bmsg->ifindex, i);

		err = pp->pp_cb((struct nl_object *) bvlan, pp);
		if (err) {
			rtnl_bridge_vlan_put(bvlan);
			return err;
		}
	}

	return 0;
}

static int bridge_vlan_parse_gopts(struct nl_cache_ops *ops, struct nlmsghdr *nlh,
				struct nlattr *entry, struct br_vlan_msg *bmsg,
				uint32_t br_ifindex, struct nl_parser_param *pp)
{
	struct nlattr *tb[BRIDGE_VLANDB_GOPTS_MAX + 1];
	uint16_t vid = 0, range = 0, msti = 0;
	int err, i;

	nla_parse_nested(tb, BRIDGE_VLANDB_GOPTS_MAX, entry,
			 br_vlandb_gopts_policy);

	if (tb[BRIDGE_VLANDB_GOPTS_ID])
		vid = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_ID]);

	if (tb[BRIDGE_VLANDB_GOPTS_RANGE])
		range = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_RANGE]);
	else
		range = vid;

	if (tb[BRIDGE_VLANDB_GOPTS_MSTI])
		msti = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_MSTI]);

	if (!vid)
		return -EINVAL;


	for (i = vid; i <= range; i++) {
		struct rtnl_bridge_vlan *bvlan = rtnl_bridge_vlan_alloc();

		if (!bvlan)
			return -ENOMEM;

		bvlan->ce_msgtype = nlh->nlmsg_type;
		bvlan->bv_ifindex = br_ifindex;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_IFINDEX;
		bvlan->family = bmsg->family;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_FAMILY;
		bvlan->vlan_id = i;
		bvlan->ce_mask |= BRIDGE_VLAN_ATTR_VID;
		bvlan->msti = msti;

		NL_DBG(2, "br=%i vid=%i msti=%i.\n", br_ifindex, i, msti);

		err = pp->pp_cb((struct nl_object *) bvlan, pp);
		if (err) {
			rtnl_bridge_vlan_put(bvlan);
			return err;
		}
	}

	return 0;
}


static int bridge_vlan_msg_parser(struct nl_cache_ops *ops,
				  struct sockaddr_nl *who, struct nlmsghdr *nlh,
				  struct nl_parser_param *pp)
{
	int err = 0, rem;
	struct nlattr *tb[BRIDGE_VLANDB_MAX + 1];
	struct br_vlan_msg *bmsg = nlmsg_data(nlh);
	struct nl_cache *link_cache = NULL;
	struct rtnl_link *link = NULL;
	uint32_t br_ifindex = 0;
	struct nlattr *pos;

	err = nlmsg_parse(nlh, sizeof(struct br_vlan_msg), tb,
			  BRIDGE_VLANDB_MAX, br_vlandb_policy);
	if (err < 0)
		return err;

	rem = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*bmsg));

	link_cache = __nl_cache_mngt_require("route/link");
	if (!link_cache) {
		NL_DBG(2, "Failed to get link cache.\n");
		return 0;
	}

	link = rtnl_link_get(link_cache, bmsg->ifindex);
	if (!link) {
		NL_DBG(2, "Failed to find link for ifindex %i.\n", bmsg->ifindex);
		return 0;
	}

	if (rtnl_link_get_master(link) > 0)
		br_ifindex = rtnl_link_get_master(link);
	else
		br_ifindex = bmsg->ifindex;
	rtnl_link_put(link);

	for (pos = nlmsg_attrdata(nlh, sizeof(*bmsg));
	     nla_ok(pos, rem); pos = nla_next(pos, &rem)) {
		switch (nla_type(pos)) {
		case BRIDGE_VLANDB_ENTRY:
			err = bridge_vlan_parse_entry(ops, nlh, pos, bmsg, br_ifindex, pp);
			break;
		case BRIDGE_VLANDB_GLOBAL_OPTIONS:
			err = bridge_vlan_parse_gopts(ops, nlh, pos, bmsg, br_ifindex, pp);
			break;
		}
	}

	return 0;
}

static void bridge_vlan_constructor(struct nl_object *c)
{
	struct rtnl_bridge_vlan *bv = (struct rtnl_bridge_vlan *) c;

	nl_init_list_head(&bv->bv_ports);
}

static void bridge_vlan_free_data(struct nl_object *c)
{
	struct rtnl_bridge_vlan *bv = (struct rtnl_bridge_vlan *) c;
	struct rtnl_vlan_port *vp, *tmp;

	if (bv == NULL)
		return;

	nl_list_for_each_entry_safe(vp, tmp, &bv->bv_ports, bvp_list) {
		rtnl_bridge_vlan_remove_port(bv, vp);
		rtnl_bridge_vp_free(vp);
	}
}

static int bridge_vlan_update(struct nl_object *old_obj, struct nl_object *new_obj)
{
	struct rtnl_bridge_vlan *new_bridge_vlan = (struct rtnl_bridge_vlan *) new_obj;
	struct rtnl_bridge_vlan *old_bridge_vlan = (struct rtnl_bridge_vlan *) old_obj;
	struct rtnl_vlan_port *new_vp;
	int action = new_obj->ce_msgtype;

	if (new_bridge_vlan->bv_nr_ports == 0) {
		old_bridge_vlan->msti = new_bridge_vlan->msti;
		return NLE_SUCCESS;
	}

	new_vp = rtnl_bridge_vlan_port_n(new_bridge_vlan, 0);
	if (!new_vp) {
		return -NLE_OPNOTSUPP;
	}

	switch(action) {
	case RTM_NEWVLAN: {
		struct rtnl_vlan_port *cloned_vp;
		struct rtnl_vlan_port *old_vp;

		nl_list_for_each_entry(old_vp, &old_bridge_vlan->bv_ports, bvp_list) {
			if (old_vp->bvp_ifindex == new_vp->bvp_ifindex) {
				old_vp->bvp_state = new_vp->bvp_state;
				return 0;
			}
		}

		cloned_vp = rtnl_bridge_vp_clone(new_vp);
		if (!cloned_vp)
			return -NLE_NOMEM;

		rtnl_bridge_vlan_add_port(old_bridge_vlan, cloned_vp);

		NL_DBG(2, "Bridge vlan obj %p updated. Added "
			"port %p ifindex %i\n", old_bridge_vlan, cloned_vp,
			cloned_vp->bvp_ifindex);
	}
		break;
	case RTM_DELVLAN: {
		struct rtnl_vlan_port *old_vp;

		/* if last port, delete the whole object */
		if (old_bridge_vlan->bv_nr_ports <= 1)
			return -NLE_OPNOTSUPP;

		nl_list_for_each_entry(old_vp, &old_bridge_vlan->bv_ports, bvp_list) {
			if (old_vp->bvp_ifindex == new_vp->bvp_ifindex) {
				rtnl_bridge_vlan_remove_port(old_bridge_vlan, old_vp);

				NL_DBG(2, "Bridge vlan obj %p updated. Removed "
					"port %p ifindex %i\n", old_bridge_vlan,
					old_vp, old_vp->bvp_ifindex);

				rtnl_bridge_vp_free(old_vp);
				break;
			}
		}
	}
		break;
	default:
		NL_DBG(2, "Unknown action associated "
			"to object %p during vlan update\n", new_obj);
		return -NLE_OPNOTSUPP;
	}

	return NLE_SUCCESS;
}

static struct nl_af_group br_vlan_groups[] = {
	/* intentionally twice to force libnl to do request_update twice */
	{AF_BRIDGE, RTNLGRP_BRVLAN},
	{AF_BRIDGE, RTNLGRP_BRVLAN},
	{END_OF_GROUP_LIST},
};

static struct nl_object_ops bridge_vlan_obj_ops = {
	.oo_name = "route/bridgevlan",
	.oo_size = sizeof(struct rtnl_bridge_vlan),
	.oo_dump = {
		    [NL_DUMP_LINE] = br_vlan_dump_line,
		    [NL_DUMP_DETAILS] = br_vlan_dump_line,
		    [NL_DUMP_STATS] = br_vlan_dump_line,
		    },
	.oo_constructor		= bridge_vlan_constructor,
	.oo_free_data		= bridge_vlan_free_data,
	.oo_update		= bridge_vlan_update,
	.oo_compare		= bridge_vlan_compare,
	.oo_id_attrs = BRIDGE_VLAN_ATTR_IFINDEX | BRIDGE_VLAN_ATTR_VID,
};

static struct nl_cache_ops bridge_vlan_ops = {
	.co_name = "route/bridgevlan",
	.co_hdrsize = sizeof(struct br_vlan_msg),
	.co_msgtypes = {
			{RTM_NEWVLAN, NL_ACT_NEW, "new"},
			{RTM_DELVLAN, NL_ACT_DEL, "del"},
			{RTM_GETVLAN, NL_ACT_GET, "get"},
			END_OF_MSGTYPES_LIST,
			},
	.co_protocol = NETLINK_ROUTE,
	.co_groups = br_vlan_groups,
	.co_request_update = bridge_vlan_request_update,
	.co_msg_parser = bridge_vlan_msg_parser,
	.co_obj_ops = &bridge_vlan_obj_ops,
};

/**
 * @name Cache Management
 * @{
 */
int rtnl_bridge_vlan_alloc_cache(struct nl_sock *sk, struct nl_cache **result)
{
	return nl_cache_alloc_and_fill(&bridge_vlan_ops, sk, result);
}

/**
 * Build a bridge vlan cache including all Bridge VLAN entries currently configured in the kernel.
 * @arg sock		Netlink socket.
 * @arg result		Pointer to store resulting cache.
 * @arg flags		Flags to apply to cache before filling
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_bridge_vlan_alloc_cache_flags(struct nl_sock *sock,
				       struct nl_cache **result,
				       unsigned int flags)
{
	struct nl_cache *cache = NULL;
	int err;

	cache = nl_cache_alloc(&bridge_vlan_ops);
	if (!cache)
		return -NLE_NOMEM;

	nl_cache_set_flags(cache, flags);

	if (sock && (err = nl_cache_refill(sock, cache)) < 0) {
		nl_cache_free(cache);
		return err;
	}

	*result = cache;
	return 0;
}

/** @} */

/**
 * @name Add / Modify
 * @{
 */

static int build_bridge_vlan_msg(int cmd, struct br_vlan_msg *hdr,
				 struct rtnl_bridge_vlan *link, int flags,
				 struct nl_msg **result)
{
	struct nl_msg *msg;
	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -NLE_NOMEM;

	*result = msg;
	return 0;
}

int rtnl_bridge_vlan_build_change_request(struct rtnl_bridge_vlan *orig,
					  struct rtnl_bridge_vlan *changes,
					  int flags, struct nl_msg **result)
{
	struct br_vlan_msg bvlan = {
		.family = orig->family,
		.ifindex = orig->bv_ifindex,
	};

	return build_bridge_vlan_msg(RTM_SETLINK, &bvlan, changes, flags, result);
}

int rtnl_bridge_vlan_change(struct nl_sock *sk, struct rtnl_bridge_vlan *orig,
			    struct rtnl_bridge_vlan *changes, int flags)
{
	struct nl_msg *msg;
	int err;

	err = rtnl_bridge_vlan_build_change_request(orig, changes, flags, &msg);
	if (err)
		return err;

	BUG_ON(msg->nm_nlh->nlmsg_seq != NL_AUTO_SEQ);
retry:
	err = nl_send_auto_complete(sk, msg);
	if (err < 0)
		goto errout;

	err = wait_for_ack(sk);
	if (err == -NLE_OPNOTSUPP && msg->nm_nlh->nlmsg_type == RTM_NEWLINK) {
		msg->nm_nlh->nlmsg_type = RTM_SETLINK;
		msg->nm_nlh->nlmsg_seq = NL_AUTO_SEQ;
		goto retry;
	}

errout:
	nlmsg_free(msg);
	return err;
}

/** @} */

/**
 * @name Get/ Set
 * @{
 */

struct rtnl_bridge_vlan *rtnl_bridge_vlan_get(struct nl_cache *cache,
					      int ifindex, int vlan)
{
	struct rtnl_bridge_vlan *bvlan_entry;

	if (cache->c_ops != &bridge_vlan_ops)
		return NULL;

	nl_list_for_each_entry(bvlan_entry, &cache->c_items, ce_list) {
		if (bvlan_entry->bv_ifindex == ifindex &&
		    bvlan_entry->vlan_id == vlan) {
			nl_object_get((struct nl_object *) bvlan_entry);
			return bvlan_entry;
		}
	}

	return NULL;

}

int rtnl_bridge_vlan_get_ifindex(struct rtnl_bridge_vlan *bvlan)
{
	return bvlan->bv_ifindex;
}

int rtnl_bridge_vlan_set_ifindex(struct rtnl_bridge_vlan *bvlan, int ifindex)
{
	bvlan->bv_ifindex = ifindex;
	bvlan->ce_mask |= BRIDGE_VLAN_ATTR_IFINDEX;

	return 0;
}

int rtnl_bridge_vlan_get_vlan_id(struct rtnl_bridge_vlan *bvlan)
{
	return bvlan->vlan_id;
}

int rtnl_bridge_vlan_set_vlan_id(struct rtnl_bridge_vlan *bvlan, uint16_t vid)
{
	bvlan->vlan_id = vid;
	bvlan->ce_mask |= BRIDGE_VLAN_ATTR_VID;

	return 0;
}

int rtnl_bridge_vp_get_ifindex(struct rtnl_vlan_port *vp, uint32_t *ifindex)
{
	*ifindex = vp->bvp_ifindex;

	return 0;
}

int rtnl_bridge_vp_set_ifindex(struct rtnl_vlan_port *vp, uint32_t ifindex)
{
	vp->bvp_ifindex = ifindex;

	return 0;
}
int rtnl_bridge_vp_get_state(struct rtnl_vlan_port *vp, uint8_t *state)
{
	*state = vp->bvp_state;

	return 0;
}

int rtnl_bridge_vp_set_state(struct rtnl_vlan_port *vp, uint8_t state)
{
	vp->bvp_state = state;

	return 0;
}

/** @} */

struct rtnl_bridge_vlan *rtnl_bridge_vlan_alloc(void)
{
	return (struct rtnl_bridge_vlan *)nl_object_alloc(&bridge_vlan_obj_ops);
}

void rtnl_bridge_vlan_put(struct rtnl_bridge_vlan *bvlan)
{
	nl_object_put((struct nl_object *) bvlan);
}

static void _nl_init bridge_vlan_init(void)
{
	nl_cache_mngt_register(&bridge_vlan_ops);
}

static void _nl_exit bridge_vlan_exit(void)
{
	nl_cache_mngt_register(&bridge_vlan_ops);
}

/** @} */
