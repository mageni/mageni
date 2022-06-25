###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_043.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2007:043
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The SUSE Linux 10.0 and openSUSE 10.2 have been updated to fix various
  security problems.

  Please note that the SUSE Linux 10.0 has been released some weeks ago.

  The SUSE Linux 10.1 is affected by some of those problems but will
  be updated in some weeks to merge back with the SLE10 Service Pack
  1 kernel.

  - CVE-2007-1357: A denial of service problem against the AppleTalk
  protocol was fixed.  A remote attacker in the same AppleTalk
  network segment could cause the machine to crash if it has AppleTalk
  protocol loaded.

  - CVE-2007-1861: The nl_fib_lookup function in net/ipv4/fib_frontend.c
  allows attackers to cause a denial of service (kernel panic) via
  NETLINK_FIB_LOOKUP replies, which trigger infinite recursion and
  a stack overflow.

  - CVE-2007-1496: nfnetlink_log in netfilter allows attackers to cause
  a denial of service (crash) via unspecified vectors involving the
  (1) nfulnl_recv_config function, (2) using &quot;multiple packets per
  netlink message&quot;, and (3) bridged packets, which trigger a NULL
  pointer dereference.

  - CVE-2007-1497: nf_conntrack in netfilter does not set nfctinfo
  during reassembly of fragmented packets, which leaves the default
  value as IP_CT_ESTABLISHED and might allow remote attackers to
  bypass certain rulesets using IPv6 fragments.

  Please note that the connection tracking option for IPv6 is not
  enabled in any currently shipping SUSE Linux kernel, so it does
  not affect SUSE Linux default kernels.

  - CVE-2007-1592: A local user could affect a double-free of a ipv6
  structure potentially causing a local denial of service attack.

  - CVE-2006-7203: The compat_sys_mount function in fs/compat.c allows
  local users to cause a denial of service (NULL pointer dereference
  and oops) by mounting a smbfs file system in compatibility mode
  (&quot;mount -t smbfs&quot;).

  - CVE-2007-2453: Seeding of the kernel random generator on boot did
  not work correctly due to a programming mistake and so the kernel
  might have more predictable random numbers than assured.

  - CVE-2007-2876: A NULL pointer dereference in SCTP connection
  tracking could be caused by a remote attacker by sending specially
  crafted packets.

  Note that this requires SCTP set-up and active to be exploitable.

  Also some non-security bugs were fixed.";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.2, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309348");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-7203", "CVE-2007-1357", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1861", "CVE-2007-2453", "CVE-2007-2876");
  script_name( "SuSE Update for kernel SUSE-SA:2007:043");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.18.8~0.5", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
