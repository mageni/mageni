###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libgd2 USN-3117-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842934");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-08 15:52:51 +0530 (Tue, 08 Nov 2016)");
  script_cve_id("CVE-2016-6911", "CVE-2016-7568", "CVE-2016-8670");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for libgd2 USN-3117-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ibrahim El-Sayed discovered that the GD
  library incorrectly handled certain malformed Tiff images. If a user or
  automated system were tricked into processing a specially crafted Tiff image,
  an attacker could cause a denial of service. (CVE-2016-6911)

Ke Liu discovered that the GD library incorrectly handled certain integers
when processing WebP images. If a user or automated system were tricked
into processing a specially crafted WebP image, an attacker could cause a
denial of service, or possibly execute arbitrary code. This issue only
applied to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-7568)

Emmanuel Law discovered that the GD library incorrectly handled certain
strings when creating images. If a user or automated system were tricked
into processing a specially crafted image, an attacker could cause a denial
of service, or possibly execute arbitrary code. (CVE-2016-8670)");
  script_tag(name:"affected", value:"libgd2 on Ubuntu 16.04 LTS,
  Ubuntu 16.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3117-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS|16\.10)");

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

  if ((res = isdpkgvuln(pkg:"libgd3:i386", ver:"2.1.0-3ubuntu0.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgd3:amd64", ver:"2.1.0-3ubuntu0.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libgd2-noxpm:i386", ver:"2.0.36~rc1~dfsg-6ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libgd2-noxpm:amd64", ver:"2.0.36~rc1~dfsg-6ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgd2-xpm:i386", ver:"2.0.36~rc1~dfsg-6ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libgd2-xpm:amd64", ver:"2.0.36~rc1~dfsg-6ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libgd3:i386", ver:"2.1.1-4ubuntu0.16.04.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libgd3:amd64", ver:"2.1.1-4ubuntu0.16.04.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"libgd3:i386", ver:"2.2.1-1ubuntu3.2", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libgd3:amd64", ver:"2.2.1-1ubuntu3.2", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
