###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xorg-x11-apps CESA-2013:0502 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019553.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881640");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:17 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2011-2504");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for xorg-x11-apps CESA-2013:0502 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-apps'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xorg-x11-apps on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Core X11 clients packages provide the xorg-x11-utils,
  xorg-x11-server-utils, and xorg-x11-apps clients that ship with the X
  Window System.

  It was found that the x11perfcomp utility included the current working
  directory in its PATH environment variable. Running x11perfcomp in an
  attacker-controlled directory would cause arbitrary code execution with
  the privileges of the user running x11perfcomp. (CVE-2011-2504)

  Also with this update, the xorg-x11-utils and xorg-x11-server-utils
  packages have been upgraded to upstream version 7.5, and the xorg-x11-apps
  package to upstream version 7.6, which provides a number of bug fixes and
  enhancements over the previous versions. (BZ#835277, BZ#835278, BZ#835281)

  All users of xorg-x11-utils, xorg-x11-server-utils, and xorg-x11-apps are
  advised to upgrade to these updated packages, which fix these issues and
  add these enhancements.");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-apps", rpm:"xorg-x11-apps~7.6~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
