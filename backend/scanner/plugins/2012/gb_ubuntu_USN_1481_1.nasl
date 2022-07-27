###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1481_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for php5 USN-1481-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1481-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841052");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:28:12 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-0781", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2317",
                "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for php5 USN-1481-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1481-1");
  script_tag(name:"affected", value:"php5 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain Tidy::diagnose
  operations on invalid objects. A remote attacker could use this flaw to
  cause PHP to crash, leading to a denial of service. (CVE-2012-0781)

  It was discovered that PHP incorrectly handled certain multi-file upload
  filenames. A remote attacker could use this flaw to cause a denial of
  service, or to perform a directory traversal attack. (CVE-2012-1172)

  Rubin Xu and Joseph Bonneau discovered that PHP incorrectly handled certain
  Unicode characters in passwords passed to the crypt() function. A remote
  attacker could possibly use this flaw to bypass authentication.
  (CVE-2012-2143)

  It was discovered that a Debian/Ubuntu specific patch caused PHP to
  incorrectly handle empty salt strings. A remote attacker could possibly use
  this flaw to bypass authentication. This issue only affected Ubuntu 10.04
  LTS and Ubuntu 11.04. (CVE-2012-2317)

  It was discovered that PHP, when used as a stand alone CGI processor
  for the Apache Web Server, did not properly parse and filter query
  strings. This could allow a remote attacker to execute arbitrary code
  running with the privilege of the web server, or to perform a denial of
  service. Configurations using mod_php5 and FastCGI were not vulnerable.
  (CVE-2012-2335, CVE-2012-2336)

  Alexander Gavrun discovered that the PHP Phar extension incorrectly handled
  certain malformed TAR files. A remote attacker could use this flaw to
  perform a denial of service, or possibly execute arbitrary code.
  (CVE-2012-2386)");
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

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.3.2-1ubuntu4.17", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.3.10-1ubuntu3.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.3.6-13ubuntu3.8", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.3.5-1ubuntu7.10", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.4-2ubuntu5.25", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
