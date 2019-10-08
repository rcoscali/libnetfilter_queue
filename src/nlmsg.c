/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <arpa/inet.h>
#include <time.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>

#include <libmnl/libmnl.h>

#ifndef __aligned_be64
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#endif

#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "internal.h"

/**
 * \defgroup nfq_verd Verdict helpers
 * @{
 */

/**
 * nfq_nlmsg_verdict_put - Put a verdict into a Netlink header
 * \param nlh Pointer to netlink message
 * \param id ID assigned to packet by netfilter
 * \param verdict verdict to return to netfilter (NF_ACCEPT, NF_DROP)
 *
 * See examples/nf-queue.c, line 46 for an example of how to use this function.
 * The calling sequence is \b main --> \b mnl_cb_run --> \b queue_cb -->
 * \b nfq_send_verdict --> \b nfq_nlmsg_verdict_put
 */
EXPORT_SYMBOL
void nfq_nlmsg_verdict_put(struct nlmsghdr *nlh, int id, int verdict)
{
	struct nfqnl_msg_verdict_hdr vh = {
		.verdict	= htonl(verdict),
		.id		= htonl(id),
	};
	mnl_attr_put(nlh, NFQA_VERDICT_HDR, sizeof(vh), &vh);
}

EXPORT_SYMBOL
void nfq_nlmsg_verdict_put_mark(struct nlmsghdr *nlh, uint32_t mark)
{
	mnl_attr_put_u32(nlh, NFQA_MARK, htonl(mark));
}

EXPORT_SYMBOL
void nfq_nlmsg_verdict_put_pkt(struct nlmsghdr *nlh, const void *pkt,
			       uint32_t plen)
{
	mnl_attr_put(nlh, NFQA_PAYLOAD, plen, pkt);
}

/**
 * @}
 */

/**
 * \defgroup nfq_cfg Config helpers
 * @{
 */

/**
 * nfq_nlmsg_cfg_put_cmd Add netlink config command to netlink message
 * \param nlh Pointer to netlink message
 * \param pf Packet family (e.g. AF_INET)
 * \param cmd nfqueue nfnetlink command.
 *
 * Possible commands are:
 *
 * - NFQNL_CFG_CMD_NONE: Do nothing. It can be useful to know if the queue
 *   subsystem is working.
 * - NFQNL_CFG_CMD_BIND: Binds the program to a specific queue.
 * - NFQNL_CFG_CMD_UNBIND: Unbinds the program to a specifiq queue.
 *
 * Obsolete commands:
 * - NFQNL_CFG_CMD_PF_BIND: Binds to process packets belonging to the given
 *   protocol family (ie. PF_INET, PF_INET6, etc).
 * - NFQNL_CFG_CMD_PF_UNBIND: Unbinds from processing packets belonging to the
 *   given protocol family.  Both commands are ignored by Linux kernel 3.8 and
 *   later versions.
 */
EXPORT_SYMBOL
void nfq_nlmsg_cfg_put_cmd(struct nlmsghdr *nlh, uint16_t pf, uint8_t cmd)
{
	struct nfqnl_msg_config_cmd command = {
		.command = cmd,
		.pf = htons(pf),
	};
	mnl_attr_put(nlh, NFQA_CFG_CMD, sizeof(command), &command);
}

/**
 * nfq_nlmsg_cfg_put_params Add parameter to netlink message
 * \param nlh Pointer to netlink message
 * \param mode one of NFQNL_COPY_NONE, NFQNL_COPY_META or NFQNL_COPY_PACKET
 * \param range value of parameter
 */
EXPORT_SYMBOL
void nfq_nlmsg_cfg_put_params(struct nlmsghdr *nlh, uint8_t mode, int range)
{
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(range),
		.copy_mode = mode,
	};
	mnl_attr_put(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);
}

/**
 * nfq_nlmsg_cfg_put_qmaxlen Add queue maximum length to netlink message
 * \param nlh Pointer to netlink message
 * \param queue_maxlen Maximum queue length
 */
EXPORT_SYMBOL
void nfq_nlmsg_cfg_put_qmaxlen(struct nlmsghdr *nlh, uint32_t queue_maxlen)
{
	mnl_attr_put_u32(nlh, NFQA_CFG_QUEUE_MAXLEN, htonl(queue_maxlen));
}

/**
 * @}
 */

/**
 * \defgroup nlmsg Netlink message helper functions
 * @{
 */

static int nfq_pkt_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NFQA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFQA_MARK:
	case NFQA_IFINDEX_INDEV:
	case NFQA_IFINDEX_OUTDEV:
	case NFQA_IFINDEX_PHYSINDEV:
	case NFQA_IFINDEX_PHYSOUTDEV:
	case NFQA_CAP_LEN:
	case NFQA_SKB_INFO:
	case NFQA_SECCTX:
	case NFQA_UID:
	case NFQA_GID:
	case NFQA_CT_INFO:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case NFQA_TIMESTAMP:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfqnl_msg_packet_timestamp)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_HWADDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfqnl_msg_packet_hw)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_PACKET_HDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfqnl_msg_packet_hdr)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_PAYLOAD:
	case NFQA_CT:
	case NFQA_EXP:
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/**
 * nfq_nlmsg_parse - set packet attributes from netlink message
 * \param nlh netlink message that you want to read.
 * \param attr pointer to array of attributes to set.
 *
 * This function returns MNL_CB_ERROR if any error occurs, or MNL_CB_OK on
 * success.
 */
EXPORT_SYMBOL
int nfq_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **attr)
{
	return mnl_attr_parse(nlh, sizeof(struct nfgenmsg),
			      nfq_pkt_parse_attr_cb, attr);
}

/**
 * @}
 */
