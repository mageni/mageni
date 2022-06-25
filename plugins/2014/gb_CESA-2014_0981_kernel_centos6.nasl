###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2014:0981 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881979");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-05 16:47:39 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2012-6647", "CVE-2013-7339", "CVE-2014-2672", "CVE-2014-2678",
                "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2014:0981 centos6");

  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any
Linux operating system.

  * A use-after-free flaw was found in the way the ping_init_sock() function
of the Linux kernel handled the group_info reference counter. A local,
unprivileged user could use this flaw to crash the system or, potentially,
escalate their privileges on the system. (CVE-2014-2851, Important)

  * A NULL pointer dereference flaw was found in the way the
futex_wait_requeue_pi() function of the Linux kernel's futex subsystem
handled the requeuing of certain Priority Inheritance (PI) futexes.
A local, unprivileged user could use this flaw to crash the system.
(CVE-2012-6647, Moderate)

  * A NULL pointer dereference flaw was found in the rds_ib_laddr_check()
function in the Linux kernel's implementation of Reliable Datagram Sockets
(RDS). A local, unprivileged user could use this flaw to crash the system.
(CVE-2013-7339, Moderate)

  * It was found that a remote attacker could use a race condition flaw in
the ath_tx_aggr_sleep() function to crash the system by creating large
network traffic on the system's Atheros 9k wireless network adapter.
(CVE-2014-2672, Moderate)

  * A NULL pointer dereference flaw was found in the rds_iw_laddr_check()
function in the Linux kernel's implementation of Reliable Datagram Sockets
(RDS). A local, unprivileged user could use this flaw to crash the system.
(CVE-2014-2678, Moderate)

  * A race condition flaw was found in the way the Linux kernel's mac80211
subsystem implementation handled synchronization between TX and STA wake-up
code paths. A remote attacker could use this flaw to crash the system.
(CVE-2014-2706, Moderate)

  * An out-of-bounds memory access flaw was found in the Netlink Attribute
extension of the Berkeley Packet Filter (BPF) interpreter functionality in
the Linux kernel's networking implementation. A local, unprivileged user
could use this flaw to crash the system or leak kernel memory to user space
via a specially crafted socket filter. (CVE-2014-3144, CVE-2014-3145,
Moderate)

This update also fixes several bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-July/020458.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.23.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
