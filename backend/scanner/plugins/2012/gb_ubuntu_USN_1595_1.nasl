###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1595_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for libxslt USN-1595-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1595-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841174");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-05 09:44:04 +0530 (Fri, 05 Oct 2012)");
  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for libxslt USN-1595-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1595-1");
  script_tag(name:"affected", value:"libxslt on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Chris Evans discovered that libxslt incorrectly handled generate-id XPath
  functions. If a user or automated system were tricked into processing a
  specially crafted XSLT document, a remote attacker could obtain potentially
  sensitive information. This issue only affected Ubuntu 8.04 LTS, Ubuntu
  10.04 LTS and Ubuntu 11.04. (CVE-2011-1202)

  It was discovered that libxslt incorrectly parsed certain patterns. If a
  user or automated system were tricked into processing a specially crafted
  XSLT document, a remote attacker could cause libxslt to crash, causing a
  denial of service. (CVE-2011-3970)

  Nicholas Gregoire discovered that libxslt incorrectly handled unexpected
  DTD nodes. If a user or automated system were tricked into processing a
  specially crafted XSLT document, a remote attacker could cause libxslt to
  crash, causing a denial of service. (CVE-2012-2825)

  Nicholas Gregoire discovered that libxslt incorrectly managed memory. If a
  user or automated system were tricked into processing a specially crafted
  XSLT document, a remote attacker could cause libxslt to crash, causing a
  denial of service. (CVE-2012-2870)

  Nicholas Gregoire discovered that libxslt incorrectly handled certain
  transforms. If a user or automated system were tricked into processing a
  specially crafted XSLT document, a remote attacker could cause libxslt to
  crash, causing a denial of service, or possibly execute arbitrary code.
  (CVE-2012-2871)

  Cris Neckar discovered that libxslt incorrectly managed memory. If a user
  or automated system were tricked into processing a specially crafted XSLT
  document, a remote attacker could cause libxslt to crash, causing a denial
  of service, or possibly execute arbitrary code. (CVE-2012-2893)");
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

  if ((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.26-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.26-8ubuntu1.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.26-7ubuntu0.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.26-6ubuntu0.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.22-1ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
