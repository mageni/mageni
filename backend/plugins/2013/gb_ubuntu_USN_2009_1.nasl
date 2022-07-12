###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2009_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-2009-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841612");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:56:22 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592",
                "CVE-2013-5593", "CVE-2013-5604", "CVE-2013-5595", "CVE-2013-5596",
                "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600",
                "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2009-1");

  script_tag(name:"affected", value:"firefox on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox.
If a user were tricked in to opening a specially crafted page, an attacker
could possibly exploit these to cause a denial of service via application
crash, or potentially execute arbitrary code with the privileges of the user
invoking Firefox.(CVE-2013-1739, CVE-2013-5590, CVE-2013-5591, CVE-2013-5592)

Jordi Chancel discovered that HTML select elements could display arbitrary
content. An attacker could potentially exploit this to conduct
URL spoofing or clickjacking attacks (CVE-2013-5593)

Abhishek Arya discovered a crash when processing XSLT data in some
circumstances. An attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-5604)

Dan Gohman discovered a flaw in the Javascript engine. When combined
with other vulnerabilities, an attacked could possibly exploit this
to execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-5595)

Ezra Pool discovered a crash on extremely large pages. An attacked
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-5596)

Byoungyoung Lee discovered a use-after-free when updating the offline
cache. An attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-5597)

Cody Crews discovered a way to append an iframe in to an embedded PDF
object displayed with PDF.js. An attacked could potentially exploit this
to read local files, leading to information disclosure. (CVE-2013-5598)

Multiple use-after-free flaws were discovered in Firefox. An attacker
could potentially exploit these to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-5599, CVE-2013-5600, CVE-2013-5601)

A memory corruption flaw was discovered in the Javascript engine when
using workers with direct proxies. An attacker could potentially exploit
this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-5602)

Abhishek Arya discovered a use-after-free when interacting with HTML
document templates. An attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-5603)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2009-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.10|12\.04 LTS|13\.10|13\.04)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"25.0+build3-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"25.0+build3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"25.0+build3-0ubuntu0.13.10", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"25.0+build3-0ubuntu0.13.04", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
