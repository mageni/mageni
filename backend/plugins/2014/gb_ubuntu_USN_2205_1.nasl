###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2205_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for tiff USN-2205-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841820");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-12 09:13:38 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for tiff USN-2205-1");

  script_tag(name:"affected", value:"tiff on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"Pedro Ribeiro discovered that LibTIFF incorrectly handled
certain malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4231)

Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the tiff2pdf tool. If a user or automated
system were tricked into opening a specially crafted TIFF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4232)

Murray McAllister discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. (CVE-2013-4243)

Huzaifa Sidhpurwala discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4244)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2205-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|10\.04 LTS|13\.10|12\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.3-7ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.5-2ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.2-2ubuntu0.14", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.2-4ubuntu3.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-1ubuntu2.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
