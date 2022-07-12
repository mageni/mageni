###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0169_kernel_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for kernel CESA-2018:0169 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882840");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-01 07:49:11 +0100 (Thu, 01 Feb 2018)");
  script_cve_id("CVE-2017-7542", "CVE-2017-9074", "CVE-2017-11176");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:0169 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * An integer overflow vulnerability in ip6_find_1stfragopt() function was
found. A local attacker that has privileges (of CAP_NET_RAW) to open raw
socket can cause an infinite loop inside the ip6_find_1stfragopt()
function. (CVE-2017-7542, Moderate)

  * The IPv6 fragmentation implementation in the Linux kernel does not
consider that the nexthdr field may be associated with an invalid option,
which allows local users to cause a denial of service (out-of-bounds read
and BUG) or possibly have unspecified other impact via crafted socket and
send system calls. Due to the nature of the flaw, privilege escalation
cannot be fully ruled out, although we believe it is unlikely.
(CVE-2017-9074, Moderate)

  * A use-after-free flaw was found in the Netlink functionality of the Linux
kernel networking subsystem. Due to the insufficient cleanup in the
mq_notify function, a local attacker could potentially use this flaw to
escalate their privileges on the system. (CVE-2017-11176, Moderate)

Bug Fix(es):

  * Previously, the default timeout and retry settings in the VMBus driver
were insufficient in some cases, for example when a Hyper-V host was under
a significant load. Consequently, in Windows Server 2016, Hyper-V Server
2016, and Windows Azure Platform, when running a Red Hat Enterprise Linux
Guest on the Hyper-V hypervisor, the guest failed to boot or booted with
certain Hyper-V devices missing. This update alters the timeout and retry
settings in VMBus, and Red Hat Enterprise Linux guests now boot as expected
under the described conditions. (BZ#1506145)

  * Previously, an incorrect external declaration in the be2iscsi driver
caused a kernel panic when using the systool utility. With this update, the
external declaration in be2iscsi has been fixed, and the kernel no longer
panics when using systool. (BZ#1507512)

  * Under high usage of the NFSD file system and memory pressure, if many
tasks in the Linux kernel attempted to obtain the global spinlock to clean
the Duplicate Reply Cache (DRC), these tasks stayed in an active wait in
the nfsd_reply_cache_shrink() function for up to 99% of time. Consequently,
a high load average occurred. This update fixes the bug by separating the
DRC in several parts, each with an independent spinlock. As a result, the
load and CPU utilization is no longer excessive under the described
circumstances. (BZ#1509876)

  * When attempting to attach multiple SCSI devices simultaneously, Red Hat
Enterprise Linux 6.9 on IBM z Systems sometimes became unresponsive. This
update fixes the zfcp ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-January/022756.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~696.20.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
