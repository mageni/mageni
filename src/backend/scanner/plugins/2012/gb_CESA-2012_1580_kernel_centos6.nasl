###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2012:1580 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-December/019039.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881552");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-12-26 12:06:49 +0530 (Wed, 26 Dec 2012)");
  script_cve_id("CVE-2012-2100", "CVE-2012-2375", "CVE-2012-4444", "CVE-2012-4565",
                "CVE-2012-5517", "CVE-2011-4131", "CVE-2009-4307");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2012:1580 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * It was found that the RHSA-2012:0862 update did not correctly fix the
  CVE-2011-4131 issue. A malicious Network File System version 4 (NFSv4)
  server could return a crafted reply to a GETACL request, causing a denial
  of service on the client. (CVE-2012-2375, Moderate)

  * A divide-by-zero flaw was found in the TCP Illinois congestion control
  algorithm implementation in the Linux kernel. If the TCP Illinois
  congestion control algorithm were in use (the sysctl
  net.ipv4.tcp_congestion_control variable set to 'illinois'), a local,
  unprivileged user could trigger this flaw and cause a denial of service.
  (CVE-2012-4565, Moderate)

  * A NULL pointer dereference flaw was found in the way a new node's hot
  added memory was propagated to other nodes' zonelists. By utilizing this
  newly added memory from one of the remaining nodes, a local, unprivileged
  user could use this flaw to cause a denial of service. (CVE-2012-5517,
  Moderate)

  * It was found that the initial release of Red Hat Enterprise Linux 6 did
  not correctly fix the CVE-2009-4307 issue, a divide-by-zero flaw in the
  ext4 file system code. A local, unprivileged user with the ability to mount
  an ext4 file system could use this flaw to cause a denial of service.
  (CVE-2012-2100, Low)

  * A flaw was found in the way the Linux kernel's IPv6 implementation
  handled overlapping, fragmented IPv6 packets. A remote attacker could
  potentially use this flaw to bypass protection mechanisms (such as a
  firewall or intrusion detection system (IDS)) when sending network packets
  to a target system. (CVE-2012-4444, Low)

  Red Hat would like to thank Antonios Atlasis working with Beyond Security's
  SecuriTeam Secure Disclosure program and Loganaden Velvindron of AFRINIC
  for reporting CVE-2012-4444. The CVE-2012-2375 issue was discovered by Jian
  Li of Red Hat, and CVE-2012-4565 was discovered by Rodrigo Freire of Red
  Hat.

  This update also fixes numerous bugs and adds one enhancement. Space
  precludes documenting all of these changes in this advisory. Documentation
  for these changes will be available shortly from the Red Hat Enterprise
  Linux 6.3 Technical Notes document linked to in the References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, fix these bugs and add the enhancement
  noted in the Technical Notes. The system must be rebooted for this update
  to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.19.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
