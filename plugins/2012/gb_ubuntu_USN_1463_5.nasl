###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1463_5.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for unity-2d USN-1463-5
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1463-5/");
  script_oid("1.3.6.1.4.1.25623.1.0.841057");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-28 10:37:06 +0530 (Thu, 28 Jun 2012)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for unity-2d USN-1463-5");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1463-5");
  script_tag(name:"affected", value:"unity-2d on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1463-2 fixed a bug in Unity 2D exposed by a recent Firefox update. It
  was discovered that the issue was only partially fixed on Ubuntu 11.04.
  When Thunderbird was started from the launcher, Thunderbird was still
  unable to obtain pointer grabs under certain conditions. This update fixes
  the problem.

  Original advisory details:

  USN-1463-1 fixed vulnerabilities in Firefox. The Firefox update exposed a
  bug in Unity 2D which resulted in Firefox being unable to obtain pointer
  grabs in order to open popup menus. This update fixes the problem.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"unity-2d-launcher", ver:"3.8.4.1-0ubuntu1.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
