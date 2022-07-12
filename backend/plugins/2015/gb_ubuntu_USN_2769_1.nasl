###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for commons-httpclient USN-2769-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842488");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-15 08:48:23 +0200 (Thu, 15 Oct 2015)");
  script_cve_id("CVE-2012-5783", "CVE-2012-6153", "CVE-2014-3577", "CVE-2015-5262");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for commons-httpclient USN-2769-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'commons-httpclient'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that Apache Commons HttpClient did not properly verify the
Common Name or subjectAltName fields of X.509 certificates. An attacker could
exploit this to perform a man in the middle attack to view sensitive
information or alter encrypted communications. This issue only affected Ubuntu
12.04 LTS. (CVE-2012-5783)

Florian Weimer discovered the fix for CVE-2012-5783 was incomplete for Apache
Commons HttpClient. An attacker could exploit this to perform a man in the
middle attack to view sensitive information or alter encrypted communications.
This issue only affected Ubuntu 12.04 LTS. (CVE-2012-6153)

Subodh Iyengar and Will Shackleton discovered the fix for CVE-2012-5783 was
incomplete for Apache Commons HttpClient. An attacker could exploit this to
perform a man in the middle attack to view sensitive information or alter
encrypted communications. (CVE-2014-3577)

It was discovered that Apache Commons HttpClient did not properly handle read
timeouts during HTTPS handshakes. A remote attacker could trigger this flaw to
cause a denial of service. (CVE-2015-5262)");
  script_tag(name:"affected", value:"commons-httpclient on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2769-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|12\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10.2ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10.2ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}