###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1510_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1510-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1510-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841083");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-19 10:43:29 +0530 (Thu, 19 Jul 2012)");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952",
                "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957",
                "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961",
                "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1510-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1510-1");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian Smith,
  Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey discovered
  memory safety issues affecting Thunderbird. If the user were tricked into
  opening a specially crafted page, an attacker could possibly exploit these to
  cause a denial of service via application crash, or potentially execute code
  with the privileges of the user invoking Thunderbird. (CVE-2012-1948,
  CVE-2012-1949)

  Abhishek Arya discovered four memory safety issues affecting Thunderbird. If
  the user were tricked into opening a specially crafted page, an attacker could
  possibly exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Thunderbird.
  (CVE-2012-1951, CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

  Mariusz Mlynski discovered that the address bar may be incorrectly updated.
  Calls to history.forward and history.back could be used to navigate to a site
  while the address bar still displayed the previous site. A remote attacker
  could exploit this to conduct phishing attacks. (CVE-2012-1955)

  Mario Heiderich discovered that HTML <embed> tags were not filtered out of the
  HTML <description> of RSS feeds. A remote attacker could exploit this to
  conduct cross-site scripting (XSS) attacks via javascript execution in the HTML
  feed view. (CVE-2012-1957)

  Arthur Gerkis discovered a use-after-free vulnerability. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit this to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Thunderbird.
  (CVE-2012-1958)

  Bobby Holley discovered that same-compartment security wrappers (SCSW) could be
  bypassed to allow XBL access. If the user were tricked into opening a specially
  crafted page, an attacker could possibly exploit this to execute code with the
  privileges of the user invoking Thunderbird. (CVE-2012-1959)

  Tony Payne discovered an out-of-bounds memory read in Mozilla's color
  management library (QCMS). If the user were tricked into opening a specially
  crafted color profile, an attacker could possibly exploit this to cause a
  denial of service via application crash. (CVE-2012-1960)

  Frederic Buclin discovered that the X-Frame-Options header was ignored when its
  value was specified multiple times. An attacker could exploit this to conduct
  clickjacking attack ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
