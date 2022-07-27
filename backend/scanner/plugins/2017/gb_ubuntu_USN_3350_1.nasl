###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3350_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for poppler USN-3350-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843239");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-14 15:54:55 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-2820", "CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9083",
                "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for poppler USN-3350-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Aleksandar Nikolic discovered that poppler
  incorrectly handled JPEG 2000 images. If a user or automated system were tricked
  into opening a crafted PDF file, an attacker could cause a denial of service or
  possibly execute arbitrary code with privileges of the user invoking the
  program. (CVE-2017-2820) Jiaqi Peng discovered that the poppler pdfunite tool
  incorrectly parsed certain malformed PDF documents. If a user or automated
  system were tricked into opening a crafted PDF file, an attacker could cause
  poppler to crash, resulting in a denial of service. (CVE-2017-7511) It was
  discovered that the poppler pdfunite tool incorrectly parsed certain malformed
  PDF documents. If a user or automated system were tricked into opening a crafted
  PDF file, an attacker could cause poppler to hang, resulting in a denial of
  service. (CVE-2017-7515) It was discovered that poppler incorrectly handled JPEG
  2000 images. If a user or automated system were tricked into opening a crafted
  PDF file, an attacker could cause cause poppler to crash, resulting in a denial
  of service. (CVE-2017-9083) It was discovered that poppler incorrectly handled
  memory when processing PDF documents. If a user or automated system were tricked
  into opening a crafted PDF file, an attacker could cause poppler to consume
  resources, resulting in a denial of service. (CVE-2017-9406, CVE-2017-9408)
  Alberto Garcia, Francisco Oca, and Suleman Ali discovered that the poppler
  pdftocairo tool incorrectly parsed certain malformed PDF documents. If a user or
  automated system were tricked into opening a crafted PDF file, an attacker could
  cause poppler to crash, resulting in a denial of service. (CVE-2017-9775)");
  script_tag(name:"affected", value:"poppler on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3350-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.04|16\.10|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0:i386", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0:amd64", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:i386", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:amd64", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:i386", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:amd64", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:i386", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:amd64", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler44:i386", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler44:amd64", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0v5:i386", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0v5:amd64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:i386", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:amd64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:i386", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:amd64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:i386", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:amd64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler64:i386", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler64:amd64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0v5:i386", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0v5:amd64", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:i386", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:amd64", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:i386", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:amd64", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:i386", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:amd64", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler61:i386", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler61:amd64", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0:i386", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-cpp0:amd64", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:i386", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-glib8:amd64", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:i386", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt4-4:amd64", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:i386", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler-qt5-1:amd64", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler58:i386", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpoppler58:amd64", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
