###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0747 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881717");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-19 10:05:40 +0530 (Fri, 19 Apr 2013)");
  script_cve_id("CVE-2012-6537", "CVE-2012-6542", "CVE-2012-6546", "CVE-2012-6547",
                "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-1826", "CVE-2013-0217");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:0747 centos5");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-April/019690.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A flaw was found in the Xen netback driver implementation in the Linux
  kernel. A privileged guest user with access to a para-virtualized network
  device could use this flaw to cause a long loop in netback, leading to a
  denial of service that could potentially affect the entire system.
  (CVE-2013-0216, Moderate)

  * A flaw was found in the Xen PCI device back-end driver implementation in
  the Linux kernel. A privileged guest user in a guest that has a PCI
  passthrough device could use this flaw to cause a denial of service that
  could potentially affect the entire system. (CVE-2013-0231, Moderate)

  * A NULL pointer dereference flaw was found in the IP packet transformation
  framework (XFRM) implementation in the Linux kernel. A local user who has
  the CAP_NET_ADMIN capability could use this flaw to cause a denial of
  service. (CVE-2013-1826, Moderate)

  * Information leak flaws were found in the XFRM implementation in the
  Linux kernel. A local user who has the CAP_NET_ADMIN capability could use
  these flaws to leak kernel stack memory to user-space. (CVE-2012-6537, Low)

  * An information leak flaw was found in the logical link control (LLC)
  implementation in the Linux kernel. A local, unprivileged user could use
  this flaw to leak kernel stack memory to user-space. (CVE-2012-6542, Low)

  * Two information leak flaws were found in the Linux kernel's Asynchronous
  Transfer Mode (ATM) subsystem. A local, unprivileged user could use these
  flaws to leak kernel stack memory to user-space. (CVE-2012-6546, Low)

  * An information leak flaw was found in the TUN/TAP device driver in the
  Linux kernel's networking implementation. A local user with access to a
  TUN/TAP virtual interface could use this flaw to leak kernel stack memory
  to user-space. (CVE-2012-6547, Low)

  Red Hat would like to thank the Xen project for reporting the CVE-2013-0216
  and CVE-2013-0231 issues.

  This update also fixes the following bugs:

  * The IPv4 code did not correctly update the Maximum Transfer Unit (MTU) of
  the designed interface when receiving ICMP Fragmentation Needed packets.
  Consequently, a remote host did not respond correctly to ping attempts.
  With this update, the IPv4 code has been modified so the MTU of the
  designed interface is adjusted as expected in this situation. The ping
  command now provides the expected output. (BZ#923353)

  * Previously, the be2net code expected the last word of an MCC complete ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
