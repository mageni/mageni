###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1513_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for libexif USN-1513-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1513-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841092");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-26 11:10:08 +0530 (Thu, 26 Jul 2012)");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836",
                "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for libexif USN-1513-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1513-1");
  script_tag(name:"affected", value:"libexif on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mateusz Jurczyk discovered that libexif incorrectly parsed certain
  malformed EXIF tags. If a user or automated system were tricked into
  processing a specially crafted image file, an attacker could cause libexif
  to crash, leading to a denial of service, or possibly obtain sensitive
  information. (CVE-2012-2812, CVE-2012-2813)

  Mateusz Jurczyk discovered that libexif incorrectly parsed certain
  malformed EXIF tags. If a user or automated system were tricked into
  processing a specially crafted image file, an attacker could cause libexif
  to crash, leading to a denial of service, or possibly execute arbitrary
  code. (CVE-2012-2814)

  Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
  tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service, or possibly obtain sensitive information.
  (CVE-2012-2836)

  Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
  tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service. (CVE-2012-2837)

  Dan Fandrich discovered that libexif incorrectly parsed certain malformed
  EXIF tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service, or possibly execute arbitrary code.
  (CVE-2012-2840, CVE-2012-2841)");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.19-1ubuntu0.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-2ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-1ubuntu0.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-0ubuntu1.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.16-2.1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
