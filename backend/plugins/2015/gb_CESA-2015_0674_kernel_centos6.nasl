###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:0674 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882129");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-13 05:13:29 +0100 (Fri, 13 Mar 2015)");
  script_cve_id("CVE-2014-7822", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8369", "CVE-2014-3601");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:0674 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * It was found that the Linux kernel's Infiniband subsystem did not
properly sanitize input parameters while registering memory regions from
user space via the (u)verbs API. A local user with access to a
/dev/infiniband/uverbsX device could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-8159,
Important)

  * A flaw was found in the way the Linux kernel's splice() system call
validated its parameters. On certain file systems, a local, unprivileged
user could use this flaw to write past the maximum file size, and thus
crash the system. (CVE-2014-7822, Moderate)

  * A flaw was found in the way the Linux kernel's netfilter subsystem
handled generic protocol tracking. As demonstrated in the Stream Control
Transmission Protocol (SCTP) case, a remote attacker could use this flaw to
bypass intended iptables rule restrictions when the associated connection
tracking module was not loaded on the system. (CVE-2014-8160, Moderate)

  * It was found that the fix for CVE-2014-3601 was incomplete: the Linux
kernel's kvm_iommu_map_pages() function still handled IOMMU mapping
failures incorrectly. A privileged user in a guest with an assigned host
device could use this flaw to crash the host. (CVE-2014-8369, Moderate)

Red Hat would like to thank Mellanox for reporting CVE-2014-8159, and Akira
Fujita of NEC for reporting CVE-2014-7822.

Bug fixes:

  * The maximum amount of entries in the IPv6 route table
(net.ipv6.route.max_size) was 4096, and every route towards this maximum
size limit was counted. Communication to more systems was impossible when
the limit was exceeded. Now, only cached routes are counted, which
guarantees that the kernel does not run out of memory, but the user can now
install as many routes as the memory allows until the kernel indicates it
can no longer handle the amount of memory and returns an error message.

In addition, the default 'net.ipv6.route.max_size' value has been increased
to 16384 for performance improvement reasons. (BZ#1177581)

  * When the user attempted to scan for an FCOE-served Logical Unit Number
(LUN), after an initial LUN scan, a kernel panic occurred in
bnx2fc_init_task. System scanning for LUNs is now stable after LUNs have
been added. (BZ#1179098)

  * Under certain conditions, such as when attempting to scan the network for
LUNs, a race condition in the bnx2fc driver could trigger a kernel panic in
bnx2fc_init_task. A patch fixing a locking issue that caused the race
condition has been applied, and scanning the network for LUNs no longer ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-March/020972.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.12.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}