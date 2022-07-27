###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libxml2 USN-2994-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842783");
  script_version("2019-03-29T08:13:51+0000");
  script_tag(name:"last_modification", value:"2019-03-29 08:13:51 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-06-07 05:25:23 +0200 (Tue, 07 Jun 2016)");
  script_cve_id("CVE-2015-8806", "CVE-2016-2073", "CVE-2016-3627", "CVE-2016-3705",
		"CVE-2016-4447", "CVE-2016-1762", "CVE-2016-1834", "CVE-2016-1833",
		"CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1835", "CVE-2016-1837",
		"CVE-2016-1836", "CVE-2016-1840", "CVE-2016-4449", "CVE-2016-4483");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for libxml2 USN-2994-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that libxml2 incorrectly
  handled certain malformed documents. If a user or automated system were tricked
  into opening a specially crafted document, an attacker could possibly cause
  libxml2 to crash, resulting in a denial of service. (CVE-2015-8806, CVE-2016-2073,
  CVE-2016-3627, CVE-2016-3705, CVE-2016-4447)

  It was discovered that libxml2 incorrectly handled certain malformed
  documents. If a user or automated system were tricked into opening a
  specially crafted document, an attacker could cause libxml2 to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2016-1762, CVE-2016-1834)

  Mateusz Jurczyk discovered that libxml2 incorrectly handled certain
  malformed documents. If a user or automated system were tricked into
  opening a specially crafted document, an attacker could cause libxml2 to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE-2016-1833, CVE-2016-1838, CVE-2016-1839)

  Wei Lei and Liu Yang discovered that libxml2 incorrectly handled certain
  malformed documents. If a user or automated system were tricked into
  opening a specially crafted document, an attacker could cause libxml2 to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE-2016-1835, CVE-2016-1837)

  Wei Lei and Liu Yang discovered that libxml2 incorrectly handled certain
  malformed documents. If a user or automated system were tricked into
  opening a specially crafted document, an attacker could cause libxml2 to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 15.10 and
  Ubuntu 16.04 LTS. (CVE-2016-1836)

  Kostya Serebryany discovered that libxml2 incorrectly handled certain
  malformed documents. If a user or automated system were tricked into
  opening a specially crafted document, an attacker could cause libxml2 to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE-2016-1840)

  It was discovered that libxml2 would load certain XML external entities. If
  a user or automated system were tricked into opening a specially crafted
  document, an attacker could possibly obtain access to arbitrary files or
  cause resource consumption. (CVE-2016-4449)

  Gustavo Grieco discovered that libxml2 incorrectly handled certain
  malformed documents. If a user or automated system were tricked into
  opening a specially crafted document, an attacker could possibly cause
  libxml2 to crash, resulting in a denial of service. (CVE-2016-4483)");
  script_tag(name:"affected", value:"libxml2 on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2994-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.1+dfsg1-3ubuntu4.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.1+dfsg1-3ubuntu4.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.7.8.dfsg-5.1ubuntu4.15", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.7.8.dfsg-5.1ubuntu4.15", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.3+dfsg1-1ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.3+dfsg1-1ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.2+zdfsg1-4ubuntu0.4", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.2+zdfsg1-4ubuntu0.4", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
