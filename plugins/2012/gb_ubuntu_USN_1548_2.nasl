###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1548_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-1548-2
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1548-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.841143");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:51:14 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973",
                "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956",
                "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960",
                "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964",
                "CVE-2012-1956", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967",
                "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971",
                "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3975", "CVE-2012-3976",
                "CVE-2012-3978", "CVE-2012-3980");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-1548-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1548-2");
  script_tag(name:"affected", value:"firefox on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1548-1 fixed vulnerabilities in Firefox. The new package caused a
  regression in Private Browsing which could leak sites visited to the
  browser cache. This update fixes the problem.

  Original advisory details:

  Gary Kwong, Christian Holler, Jesse Ruderman, Steve Fink, Bob Clary, Andrew
  Sutherland, Jason Smith, John Schoenick, Vladimir Vukicevic and Daniel
  Holbert discovered memory safety issues affecting Firefox. If the user were
  tricked into opening a specially crafted page, an attacker could exploit
  these to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Firefox.
  (CVE-2012-1970, CVE-2012-1971)

  Abhishek Arya discovered multiple use-after-free vulnerabilities. If the
  user were tricked into opening a specially crafted page, an attacker could
  exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Firefox.
  (CVE-2012-1972, CVE-2012-1973, CVE-2012-1974, CVE-2012-1975, CVE-2012-1976,
  CVE-2012-3956, CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
  CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

  Mariusz Mlynsk discovered that it is possible to shadow the location object
  using Object.defineProperty. This could potentially result in a cross-site
  scripting (XSS) attack against plugins. With cross-site scripting
  vulnerabilities, if a user were tricked into viewing a specially crafted
  page, a remote attacker could exploit this to modify the contents or steal
  confidential data within the same domain. (CVE-2012-1956)

  Mariusz Mlynski discovered an escalation of privilege vulnerability through
  about:newtab. This could possibly lead to potentially code execution with
  the privileges of the user invoking Firefox. (CVE-2012-3965)

  Frederic Hoguin discovered that bitmap format images with a negative height
  could potentially result in memory corruption. If the user were tricked
  into opening a specially crafted image, an attacker could exploit
  this to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Firefox.
  (CVE-2012-3966)

  It was discovered that Firefox's WebGL implementation was vulnerable to
  multiple memory safety issues. If the user were tricked into opening a
  specially crafted page, an attacker could exploit these to cause a denial
  of service via application crash, or potentially execute code with the
  privileges ...

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"15.0.1+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"15.0.1+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"15.0.1+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"15.0.1+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
