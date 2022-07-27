###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1416_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for tiff USN-1416-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1416-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840976");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-05 10:21:01 +0530 (Thu, 05 Apr 2012)");
  script_cve_id("CVE-2012-1173", "CVE-2010-4665");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for tiff USN-1416-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.10|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1416-1");
  script_tag(name:"affected", value:"tiff on Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Alexander Gavrun discovered that the TIFF library incorrectly allocated
  space for a tile. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could execute arbitrary
  code with user privileges, or crash the application, leading to a denial of
  service. (CVE-2012-1173)

  It was discovered that the tiffdump utility incorrectly handled directory
  data structures with many directory entries. If a user or automated system
  were tricked into opening a specially crafted TIFF image, a remote attacker
  could crash the application, leading to a denial of service, or possibly
  execute arbitrary code with user privileges. This issue only applied to
  Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04.
  (CVE-2010-4665)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-2ubuntu0.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.2-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.5-1ubuntu1.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-5ubuntu6.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-7ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
