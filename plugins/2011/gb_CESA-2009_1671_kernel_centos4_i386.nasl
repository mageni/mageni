###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1671 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-December/016393.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880764");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2910", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621");
  script_name("CentOS Update for kernel CESA-2009:1671 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kernel on CentOS 4");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * a flaw was found in the Realtek r8169 Ethernet driver in the Linux
  kernel. pci_unmap_single() presented a memory leak that could lead to IOMMU
  space exhaustion and a system crash. An attacker on the local network could
  trigger this flaw by using jumbo frames for large amounts of network
  traffic. (CVE-2009-3613, Important)

  * NULL pointer dereference flaws were found in the r128 driver in the Linux
  kernel. Checks to test if the Concurrent Command Engine state was
  initialized were missing in private IOCTL functions. An attacker could use
  these flaws to cause a local denial of service or escalate their
  privileges. (CVE-2009-3620, Important)

  * an information leak was found in the Linux kernel. On AMD64 systems,
  32-bit processes could access and read certain 64-bit registers by
  temporarily switching themselves to 64-bit mode. (CVE-2009-2910, Moderate)

  * the unix_stream_connect() function in the Linux kernel did not check if a
  UNIX domain socket was in the shutdown state. This could lead to a
  deadlock. A local, unprivileged user could use this flaw to cause a denial
  of service. (CVE-2009-3621, Moderate)

  This update also fixes the following bugs:

  * an iptables rule with the recent module and a hit count value greater
  than the ip_pkt_list_tot parameter (the default is 20), did not have any
  effect over packets, as the hit count could not be reached. (BZ#529306)

  * in environments that use dual-controller storage devices with the cciss
  driver, Device-Mapper Multipath maps could not be detected and configured,
  due to the cciss driver not exporting the bus attribute via sysfs. This
  attribute is now exported. (BZ#529309)

  * the kernel crashed with a divide error when a certain joystick was
  attached. (BZ#532027)

  * a bug in the mptctl_do_mpt_command() function in the mpt driver may have
  resulted in crashes during boot on i386 systems with certain adapters using
  the mpt driver, and also running the hugemem kernel. (BZ#533798)

  * on certain hardware, the igb driver was unable to detect link statuses
  correctly. This may have caused problems for network bonding, such as
  failover not occurring. (BZ#534105)

  * the RHSA-2009:1024 update introduced a regression. After updating to Red
  Hat Enterprise Linux 4.8 and rebooting, network links often failed to be
  brought up for interfaces using the forcedeth driver. 'no link during
  initialization' messages may have been logg ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.18.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
