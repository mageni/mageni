###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for piranha CESA-2014:0175 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.881883");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-17 11:39:46 +0530 (Mon, 17 Feb 2014)");
  script_cve_id("CVE-2013-6492");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for piranha CESA-2014:0175 centos6");

  script_tag(name:"affected", value:"piranha on CentOS 6");
  script_tag(name:"insight", value:"Piranha provides high-availability and load-balancing services for Red Hat
Enterprise Linux. The piranha packages contain various tools to administer
and configure the Linux Virtual Server (LVS), as well as the heartbeat and
failover components. LVS is a dynamically-adjusted kernel routing mechanism
that provides load balancing, primarily for Web and FTP servers.

It was discovered that the Piranha Configuration Tool did not properly
restrict access to its web pages. A remote attacker able to connect to the
Piranha Configuration Tool web server port could use this flaw to read or
modify the LVS configuration without providing valid administrative
credentials. (CVE-2013-6492)

This update also fixes the following bug:

  * When the lvsd service attempted to start, the sem_timedwait() function
received the interrupted function call (EINTR) error and exited, causing
the lvsd service to fail to start. With this update, EINTR errors are
correctly ignored during the start-up of the lvsd service. (BZ#1055709)

All piranha users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-February/020157.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'piranha'
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

  if ((res = isrpmvuln(pkg:"piranha", rpm:"piranha~0.8.6~4.el6_5.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
