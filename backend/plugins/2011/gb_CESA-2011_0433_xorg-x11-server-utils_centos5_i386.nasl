###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xorg-x11-server-utils CESA-2011:0433 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017321.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880499");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0465");
  script_name("CentOS Update for xorg-x11-server-utils CESA-2011:0433 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xorg-x11-server-utils on CentOS 5");
  script_tag(name:"insight", value:"The xorg-x11-server-utils package contains a collection of utilities used
  to modify and query the runtime configuration of the X.Org server. X.Org is
  an open source implementation of the X Window System.

  A flaw was found in the X.Org X server resource database utility, xrdb.
  Certain variables were not properly sanitized during the launch of a user's
  graphical session, which could possibly allow a remote attacker to execute
  arbitrary code with root privileges, if they were able to make the display
  manager execute xrdb with a specially-crafted X client hostname. For
  example, by configuring the hostname on the target system via a crafted
  DHCP reply, or by using the X Display Manager Control Protocol (XDMCP) to
  connect to that system from a host that has a special DNS name.
  (CVE-2011-0465)

  Red Hat would like to thank Matthieu Herrb for reporting this issue.
  Upstream acknowledges Sebastian Krahmer of the SuSE Security Team as the
  original reporter.

  Users of xorg-x11-server-utils should upgrade to this updated package,
  which contains a backported patch to resolve this issue. All running X.Org
  server instances must be restarted for this update to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server-utils", rpm:"xorg-x11-server-utils~7.1~5.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
