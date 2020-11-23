/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>

#ifdef INET
/*
 * Return the network number from an internet address.
 */
u_long
in_netof(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register u_long net;
	register struct in_ifaddr *ia;

	if (IN_CLASSA(i))
		net = i & IN_CLASSA_NET;
	else if (IN_CLASSB(i))
		net = i & IN_CLASSB_NET;
	else if (IN_CLASSC(i))
		net = i & IN_CLASSC_NET;
	else if (IN_CLASSD(i))
		net = i & IN_CLASSD_NET;
	else
		return (0);

	/*
	 * Check whether network is a subnet;
	 * if so, return subnet number.
	 */
	for (ia = in_ifaddr; ia; ia = ia->ia_next)
		if (net == ia->ia_net)
			return (i & ia->ia_subnetmask);
	return (net);
}

#ifndef SUBNETSARELOCAL
#define	SUBNETSARELOCAL	1
#endif
int subnetsarelocal = SUBNETSARELOCAL;
/*
 * Return 1 if an internet address is for a ``local'' host
 * (one to which we have a connection).  If subnetsarelocal
 * is true, this includes other subnets of the local net.
 * Otherwise, it includes only the directly-connected (sub)nets.
 */
in_localaddr(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register struct in_ifaddr *ia;

	if (subnetsarelocal) {
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if ((i & ia->ia_netmask) == ia->ia_net)
				return (1);
	} else {
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if ((i & ia->ia_subnetmask) == ia->ia_subnet)
				return (1);
	}
	return (0);
}

/*
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 */
in_canforward(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register u_long net;

	if (IN_EXPERIMENTAL(i) || IN_MULTICAST(i))
		return (0);
	if (IN_CLASSA(i)) {
		net = i & IN_CLASSA_NET;
		if (net == 0 || net == (IN_LOOPBACKNET << IN_CLASSA_NSHIFT))
			return (0);
	}
	return (1);
}

/*
 * Trim a mask in a sockaddr
 */
void
in_socktrim(ap)
struct sockaddr_in *ap;
{
    register char *cplim = (char *) &ap->sin_addr;
    register char *cp = (char *) (&ap->sin_addr + 1);

    ap->sin_len = 0;
    while (--cp > cplim)
        if (*cp) {
	    (ap)->sin_len = cp - (char *) (ap) + 1;
	    break;
	}
}

int	in_interfaces;		/* number of external internet interfaces */
extern	struct ifnet loif;

/*
 * Generic internet control operations (ioctl's).
 * Ifp is 0 if not an interface-specific ioctl.
 * @Param so: 指向发送 ioctl 的 socket
 * @Param cmd: 当前指令
 * @param data: 用于保存当前指令的返回值
 * @Param ifp:  指向 ifnet 或者为 null， 如果 ifp 不为 null,则会从全局变量 in_ifaddr
 * 中匹配出指向该 ifp 的 in_ifaddr 接口。如果 ifp 为 null, 那么 cmd 不会匹配当前方法中的
 * 第一个 switch 语句的任意一个 case，也不会匹配任意第二个 switch 中非默认 case
 *
 * ps: 当前方法中共存在两个 switch，第一个 switch 的作用是校验 cmd 在被第二个 switch 处理时需要的条件是否被满足
 */
/* ARGSUSED */
in_control(so, cmd, data, ifp)
	struct socket *so;
	int cmd;
	caddr_t data;
	register struct ifnet *ifp;
{
	register struct ifreq *ifr = (struct ifreq *)data;
	register struct in_ifaddr *ia = 0;
	register struct ifaddr *ifa;
	struct in_ifaddr *oia;
	struct in_aliasreq *ifra = (struct in_aliasreq *)data;
	struct sockaddr_in oldaddr;
	int error, hostIsNew, maskIsNew;
	u_long i;

	/*
	 * Find address for this interface, if it exists.
	 * in_ifaddr 是一个全局变量，维护当前系统分配的所有 internet 地址
	 */
	if (ifp)
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if (ia->ia_ifp == ifp)
				break;

	switch (cmd) {

	case SIOCAIFADDR:
	case SIOCDIFADDR:
	    // 搜索当前接口 ifnet 中与参数中地址一样的 ifaddr 节点
		if (ifra->ifra_addr.sin_family == AF_INET)
		    for (oia = ia; ia; ia = ia->ia_next) {
			if (ia->ia_ifp == ifp  &&
			    ia->ia_addr.sin_addr.s_addr ==
				ifra->ifra_addr.sin_addr.s_addr)
			    break;
		}
		if (cmd == SIOCDIFADDR && ia == 0)
			return (EADDRNOTAVAIL);
		/* FALLTHROUGH */
	case SIOCSIFADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFDSTADDR:
	    // 如果不是超级用户创建的 socket，则被禁止
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);

		if (ifp == 0)
			panic("in_control");
		// 如果 ia 是 null，即当前接口 ifp 未被分配过 ip地址
		if (ia == (struct in_ifaddr *)0) {
		    // 分配一个 in_ifaddr 用于存放即将分配的 IP 地址
			oia = (struct in_ifaddr *)
				malloc(sizeof *oia, M_IFADDR, M_WAITOK);
			if (oia == (struct in_ifaddr *)NULL)
				return (ENOBUFS);
			bzero((caddr_t)oia, sizeof *oia);   // 将新分配的内内存空间统一设置为 0
			// 找到 in_ifaddr 链表的尾部，将新分配的 in_ifaddr 链接到链表中
			if (ia = in_ifaddr) {
				for ( ; ia->ia_next; ia = ia->ia_next)
					continue;
				ia->ia_next = oia;
			} else
				in_ifaddr = oia;
			ia = oia;
			// 将新分配的 in_ifaddr 链接到 ifnet 地址链表的尾部
			if (ifa = ifp->if_addrlist) {
				for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
					continue;
				ifa->ifa_next = (struct ifaddr *) ia;
			} else
				ifp->if_addrlist = (struct ifaddr *) ia;
            // 将 in_ifaddr 中的数据初始化好
			ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
			ia->ia_ifa.ifa_dstaddr
					= (struct sockaddr *)&ia->ia_dstaddr;
			ia->ia_ifa.ifa_netmask
					= (struct sockaddr *)&ia->ia_sockmask;
			ia->ia_sockmask.sin_len = 8;
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sin_len = sizeof(ia->ia_addr);
				ia->ia_broadaddr.sin_family = AF_INET;
			}
			ia->ia_ifp = ifp;
			if (ifp != &loif)
				in_interfaces++;
		}
		break;

	case SIOCSIFBRDADDR:
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
		/* FALLTHROUGH */

	case SIOCGIFADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCGIFBRDADDR:
		if (ia == (struct in_ifaddr *)0)
			return (EADDRNOTAVAIL);
		break;
	}

	/**
	 * 第二个 switch
	 */
	switch (cmd) {

	case SIOCGIFADDR:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_addr;
		break;

	case SIOCGIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0)
			return (EINVAL);
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_broadaddr;
		break;

	case SIOCGIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_dstaddr;
		break;

	case SIOCGIFNETMASK:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_sockmask;
		break;
    // 点对点网络设置链路端点地址
	case SIOCSIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		oldaddr = ia->ia_dstaddr;
		ia->ia_dstaddr = *(struct sockaddr_in *)&ifr->ifr_dstaddr;
		if (ifp->if_ioctl && (error = (*ifp->if_ioctl)
					(ifp, SIOCSIFDSTADDR, (caddr_t)ia))) {
			ia->ia_dstaddr = oldaddr;
			return (error);
		}
		// 如果之前已经路由信息已经安装过
		if (ia->ia_flags & IFA_ROUTE) {
			ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&oldaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);   // 删除老地址的路由信息
			ia->ia_ifa.ifa_dstaddr =
					(struct sockaddr *)&ia->ia_dstaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_HOST|RTF_UP);  // 初始化新地址的路由信息
		}
		break;
	// 设置广播地址
	case SIOCSIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0)
			return (EINVAL);
		ia->ia_broadaddr = *(struct sockaddr_in *)&ifr->ifr_broadaddr;
		break;
	// 设置IP地址，
	case SIOCSIFADDR:
		return (in_ifinit(ifp, ia,
		    (struct sockaddr_in *) &ifr->ifr_addr, 1));  // IP 地址已经在 ifr->ifr_addr 中了

	case SIOCSIFNETMASK:
		i = ifra->ifra_addr.sin_addr.s_addr;
		ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
		break;

	case SIOCAIFADDR:
	    // 因为 SIOCAIFADDR 可以给接口增加一个新地址，或者改变其中一个地址关联的信息
	    // maskIsNew、hostIsNew 可以用来跟踪什么内容被改变了，以便在当前命令处理的末尾
	    // 可以由这个这两个字段来决定是否要更新路由
		maskIsNew = 0;
		hostIsNew = 1;    // 默认是更新地址
		error = 0;
		// 在当前方法的第一个 switch 中可能没有找到 ia，这里 ia 可能等于 0
		if (ia->ia_addr.sin_family == AF_INET) {
		    // 判断是否是更新地址，如果不是，则将 hostIsNew 更新为 0
			if (ifra->ifra_addr.sin_len == 0) {
				ifra->ifra_addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (ifra->ifra_addr.sin_addr.s_addr ==
					       ia->ia_addr.sin_addr.s_addr)
				hostIsNew = 0;
		}
		// 如果网络掩码存在
		if (ifra->ifra_mask.sin_len) {
			in_ifscrub(ifp, ia);
			ia->ia_sockmask = ifra->ifra_mask;
			ia->ia_subnetmask =
			     ntohl(ia->ia_sockmask.sin_addr.s_addr);
			maskIsNew = 1;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (ifra->ifra_dstaddr.sin_family == AF_INET)) {
			in_ifscrub(ifp, ia);
			ia->ia_dstaddr = ifra->ifra_dstaddr;
			maskIsNew  = 1; /* We lie; but the effect's the same */
		}
		if (ifra->ifra_addr.sin_family == AF_INET &&
		    (hostIsNew || maskIsNew))
			error = in_ifinit(ifp, ia, &ifra->ifra_addr, 0);   //更新信息
		// 如果当前接口支持多播
		if ((ifp->if_flags & IFF_BROADCAST) &&
		    (ifra->ifra_broadaddr.sin_family == AF_INET))
			ia->ia_broadaddr = ifra->ifra_broadaddr;
		return (error);

	case SIOCDIFADDR:
		in_ifscrub(ifp, ia);  // 清除路由信息
		// 在 ifnet 的地址链表中清除 ia
		if ((ifa = ifp->if_addrlist) == (struct ifaddr *)ia)
			ifp->if_addrlist = ifa->ifa_next;
		else {
			while (ifa->ifa_next &&
			       (ifa->ifa_next != (struct ifaddr *)ia))
				    ifa = ifa->ifa_next;
			if (ifa->ifa_next)
				ifa->ifa_next = ((struct ifaddr *)ia)->ifa_next;
			else
				printf("Couldn't unlink inifaddr from ifp\n");
		}
		// 在全局的地址链表中删除当前地址
		oia = ia;
		if (oia == (ia = in_ifaddr))
			in_ifaddr = ia->ia_next;
		else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next)
				ia->ia_next = oia->ia_next;
			else
				printf("Didn't unlink inifadr from list\n");
		}
		IFAFREE((&oia->ia_ifa));   // 释放给该地址分配的内存空间
		break;

	default:
		if (ifp == 0 || ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		// 如果 ifp<Struct ifnet> 存在，并且 ifp<Struct ifnet>中的 if_ioctl 存在。
		// 则进入 if_ioctl 中进行设备相关的处理
		return ((*ifp->if_ioctl)(ifp, cmd, data));
	}
	return (0);
}

/*
 * Delete any existing route for an interface.
 */
void
in_ifscrub(ifp, ia)
	register struct ifnet *ifp;
	register struct in_ifaddr *ia;
{
    // IFA_ROUTE 表示 routing entry installed
	if ((ia->ia_flags & IFA_ROUTE) == 0)
		return;
	if (ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))
		rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
	else
		rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
	ia->ia_flags &= ~IFA_ROUTE;
}

/*
 * Initialize an interface's internet address
 * and routing table entry.
 */
in_ifinit(ifp, ia, sin, scrub)
	register struct ifnet *ifp;
	register struct in_ifaddr *ia;
	struct sockaddr_in *sin;
	int scrub;    // 标识如果当前接口存在路由信息，是否要删除
{
	register u_long i = ntohl(sin->sin_addr.s_addr);
	struct sockaddr_in oldaddr;   // 存储老的地址，在 IP 地址设置过程中，如果出错，则需要将老地址恢复
	int s = splimp(), flags = RTF_UP, error, ether_output();

	oldaddr = ia->ia_addr;
	ia->ia_addr = *sin;
	/*
	 * Give the interface a chance to initialize
	 * if this is its first address,
	 * and to validate the address if necessary.
	 * 如果 ifnet 中 if_ioctl 存在，则调用
	 * ps：if_ioctl 是 ifnet 初始化时，放上去的 leioctl、slioctl、loioctl
	 *
	 *  这里调用 leioctl 主要是用于初始化一下数据
	 */
	if (ifp->if_ioctl &&
	    (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia))) {
		splx(s);
		ia->ia_addr = oldaddr;
		return (error);
	}
	// 如果是以太网接口， arp_rtrequest 被选中
	if (ifp->if_output == ether_output) { /* XXX: Another Kludge */
		ia->ia_ifa.ifa_rtrequest = arp_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
	}
	splx(s);
	// 清除接口存在的路由信息
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		in_ifscrub(ifp, ia);   // 将 oldaddr 的所有地址设置为无效
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	//
	if (IN_CLASSA(i))
		ia->ia_netmask = IN_CLASSA_NET;
	else if (IN_CLASSB(i))
		ia->ia_netmask = IN_CLASSB_NET;
	else
		ia->ia_netmask = IN_CLASSC_NET;
	/*
	 * The subnet mask usually includes at least the standard network part,
	 * but may may be smaller in the case of supernetting.
	 * If it is set, we believe it.
	 */
	if (ia->ia_subnetmask == 0) {
		ia->ia_subnetmask = ia->ia_netmask;
		ia->ia_sockmask.sin_addr.s_addr = htonl(ia->ia_subnetmask);
	} else
		ia->ia_netmask &= ia->ia_subnetmask;
	ia->ia_net = i & ia->ia_netmask;     // 提取网络号
	ia->ia_subnet = i & ia->ia_subnetmask;  // 提取子网号
	in_socktrim(&ia->ia_sockmask);
	/*
	 * Add route for the network.
	 * 为新地址建立路由信息
	 */
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	// 如果当前接口支持广播
	if (ifp->if_flags & IFF_BROADCAST) {
		ia->ia_broadaddr.sin_addr.s_addr =
			htonl(ia->ia_subnet | ~ia->ia_subnetmask);
		ia->ia_netbroadcast.s_addr =
			htonl(ia->ia_net | ~ ia->ia_netmask);
	}
	else if (ifp->if_flags & IFF_LOOPBACK) {
		ia->ia_ifa.ifa_dstaddr = ia->ia_ifa.ifa_addr;
		flags |= RTF_HOST;
	} else if (ifp->if_flags & IFF_POINTOPOINT) {
	    // 如果是点对点，并且还没有链路对端的地址，则直接返回
		if (ia->ia_dstaddr.sin_family != AF_INET)
			return (0);
		flags |= RTF_HOST;
	}
	if ((error = rtinit(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0)
		ia->ia_flags |= IFA_ROUTE;    // route is installed
	/*
	 * If the interface supports multicast, join the "all hosts"
	 * multicast group on that interface.
	 * ps: 12 chapter
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		struct in_addr addr;

		addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		in_addmulti(&addr, ifp);
	}
	return (error);
}


/*
 * Return 1 if the address might be a local broadcast address.
 */
in_broadcast(in, ifp)
	struct in_addr in;
        struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	u_long t;

	if (in.s_addr == INADDR_BROADCAST ||
	    in.s_addr == INADDR_ANY)
		return 1;
	if ((ifp->if_flags & IFF_BROADCAST) == 0)
		return 0;
	t = ntohl(in.s_addr);
	/*
	 * Look through the list of addresses for a match
	 * with a broadcast address.
	 */
#define ia ((struct in_ifaddr *)ifa)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    (in.s_addr == ia->ia_broadaddr.sin_addr.s_addr ||
		     in.s_addr == ia->ia_netbroadcast.s_addr ||
		     /*
		      * Check for old-style (host 0) broadcast.
		      */
		     t == ia->ia_subnet || t == ia->ia_net))
			    return 1;
	return (0);
#undef ia
}
/*
 * Add an address to the list of IP multicast addresses for a given interface.
 */
struct in_multi *
in_addmulti(ap, ifp)
	register struct in_addr *ap;
	register struct ifnet *ifp;
{
	register struct in_multi *inm;
	struct ifreq ifr;
	struct in_ifaddr *ia;
	int s = splnet();

	/*
	 * See if address already in list.
	 */
	IN_LOOKUP_MULTI(*ap, ifp, inm);
	if (inm != NULL) {
		/*
		 * Found it; just increment the reference count.
		 */
		++inm->inm_refcount;
	}
	else {
		/*
		 * New address; allocate a new multicast record
		 * and link it into the interface's multicast list.
		 */
		inm = (struct in_multi *)malloc(sizeof(*inm),
		    M_IPMADDR, M_NOWAIT);
		if (inm == NULL) {
			splx(s);
			return (NULL);
		}
		inm->inm_addr = *ap;
		inm->inm_ifp = ifp;
		inm->inm_refcount = 1;
		IFP_TO_IA(ifp, ia);
		if (ia == NULL) {
			free(inm, M_IPMADDR);
			splx(s);
			return (NULL);
		}
		inm->inm_ia = ia;
		inm->inm_next = ia->ia_multiaddrs;
		ia->ia_multiaddrs = inm;
		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr = *ap;
		if ((ifp->if_ioctl == NULL) ||
		    (*ifp->if_ioctl)(ifp, SIOCADDMULTI,(caddr_t)&ifr) != 0) {
			ia->ia_multiaddrs = inm->inm_next;
			free(inm, M_IPMADDR);
			splx(s);
			return (NULL);
		}
		/*
		 * Let IGMP know that we have joined a new IP multicast group.
		 */
		igmp_joingroup(inm);
	}
	splx(s);
	return (inm);
}

/*
 * Delete a multicast address record.
 */
int
in_delmulti(inm)
	register struct in_multi *inm;
{
	register struct in_multi **p;
	struct ifreq ifr;
	int s = splnet();

	if (--inm->inm_refcount == 0) {
		/*
		 * No remaining claims to this record; let IGMP know that
		 * we are leaving the multicast group.
		 */
		igmp_leavegroup(inm);
		/*
		 * Unlink from list.
		 */
		for (p = &inm->inm_ia->ia_multiaddrs;
		     *p != inm;
		     p = &(*p)->inm_next)
			 continue;
		*p = (*p)->inm_next;
		/*
		 * Notify the network driver to update its multicast reception
		 * filter.
		 */
		((struct sockaddr_in *)&(ifr.ifr_addr))->sin_family = AF_INET;
		((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr =
								inm->inm_addr;
		(*inm->inm_ifp->if_ioctl)(inm->inm_ifp, SIOCDELMULTI,
							     (caddr_t)&ifr);
		free(inm, M_IPMADDR);
	}
	splx(s);
}
#endif
