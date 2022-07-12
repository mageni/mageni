###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1149_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-1149-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1149-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.840692");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-07-08 16:31:28 +0200 (Fri, 08 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371", "CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2363", "CVE-2011-2362");
  script_name("Ubuntu Update for firefox USN-1149-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|10\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1149-2");
  script_tag(name:"affected", value:"firefox on Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1149-1 fixed vulnerabilities in Firefox. Unfortunately, a regression
  was introduced that prevented cookies from being stored properly when the
  hostname was a single character. This update fixes the problem. We
  apologize for the inconvenience.

  Original advisory details:

  Multiple memory vulnerabilities were discovered in the browser rendering
  engine. An attacker could use these to possibly execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2364, CVE-2011-2365,
  CVE-2011-2374, CVE-2011-2376)

  Martin Barbella discovered that under certain conditions, viewing a XUL
  document while JavaScript was disabled caused deleted memory to be
  accessed. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2373)

  Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
  images due to memory corruption. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2377)

  Chris Rohlf and Yan Ivnitskiy discovered an integer overflow vulnerability
  in JavaScript Arrays. An attacker could potentially use this to execute
  arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2371)

  Multiple use-after-free vulnerabilities were discovered. An attacker could
  potentially use these to execute arbitrary code with the privileges of the
  user invoking Firefox. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

  David Chan discovered that cookies did not honor same-origin conventions.
  This could potentially lead to cookie data being leaked to a third party.
  (CVE-2011-2362)");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.18+build2+nobinonly-0ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.18+build2+nobinonly-0ubuntu0.10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
