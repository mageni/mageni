###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_2930_kernel_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for kernel CESA-2017:2930 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882792");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-10-25 15:03:50 +0200 (Wed, 25 Oct 2017)");
  script_cve_id("CVE-2016-8399", "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-11176",
                "CVE-2017-14106", "CVE-2017-7184", "CVE-2017-7541", "CVE-2017-7542",
                "CVE-2017-7558");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:2930 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * Out-of-bounds kernel heap access vulnerability was found in xfrm,
kernel's IP framework for transforming packets. An error dealing with
netlink messages from an unprivileged user leads to arbitrary read/write
and privilege escalation. (CVE-2017-7184, Important)

  * A race condition issue leading to a use-after-free flaw was found in the
way the raw packet sockets are implemented in the Linux kernel networking
subsystem handling synchronization. A local user able to open a raw packet
socket (requires the CAP_NET_RAW capability) could use this flaw to elevate
their privileges on the system. (CVE-2017-1000111, Important)

  * An exploitable memory corruption flaw was found in the Linux kernel. The
append path can be erroneously switched from UFO to non-UFO in
ip_ufo_append_data() when building an UFO packet with MSG_MORE option. If
unprivileged user namespaces are available, this flaw can be exploited to
gain root privileges. (CVE-2017-1000112, Important)

  * A flaw was found in the Linux networking subsystem where a local attacker
with CAP_NET_ADMIN capabilities could cause an out-of-bounds memory access
by creating a smaller-than-expected ICMP header and sending to its
destination via sendto(). (CVE-2016-8399, Moderate)

  * Kernel memory corruption due to a buffer overflow was found in
brcmf_cfg80211_mgmt_tx() function in Linux kernels from v3.9-rc1 to
v4.13-rc1. The vulnerability can be triggered by sending a crafted
NL80211_CMD_FRAME packet via netlink. This flaw is unlikely to be triggered
remotely as certain userspace code is needed for this. An unprivileged
local user could use this flaw to induce kernel memory corruption on the
system, leading to a crash. Due to the nature of the flaw, privilege
escalation cannot be fully ruled out, although it is unlikely.
(CVE-2017-7541, Moderate)

  * An integer overflow vulnerability in ip6_find_1stfragopt() function was
found. A local attacker that has privileges (of CAP_NET_RAW) to open raw
socket can cause an infinite loop inside the ip6_find_1stfragopt()
function. (CVE-2017-7542, Moderate)

  * A kernel data leak due to an out-of-bound read was found in the Linux
kernel in inet_diag_msg_sctp{, l}addr_fill() and sctp_get_sctp_info()
functions present since version 4.7-rc1 through version 4.13. A data leak
happens when these functions fill in sockaddr data structures used to
export socket's diagnostic information. As a result, up to 100 bytes of the
slab data could be leaked to a userspace. (CVE-2017-7558, Moderate)

  * The mq_notify function in the Linux ke ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-October/022605.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~693.5.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
