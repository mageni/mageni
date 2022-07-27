###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libxml2 USN-2812-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842535");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-11-17 05:31:05 +0100 (Tue, 17 Nov 2015)");
  script_cve_id("CVE-2015-1819", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for libxml2 USN-2812-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Florian Weimer discovered that libxml2
incorrectly handled certain XML data. If a user or automated system were tricked
into opening a specially crafted document, an attacker could possibly cause resource
consumption, resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-1819)

Michal Zalewski discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-7941)

Kostya Serebryany discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7942)

Gustavo Grieco discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS. (CVE-2015-8035)");
  script_tag(name:"affected", value:"libxml2 on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2812-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|12\.04 LTS|15\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.2+dfsg1-3ubuntu0.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.2+dfsg1-3ubuntu0.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.1+dfsg1-3ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.1+dfsg1-3ubuntu4.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.7.8.dfsg-5.1ubuntu4.12", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.2+zdfsg1-4ubuntu0.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.2+zdfsg1-4ubuntu0.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
