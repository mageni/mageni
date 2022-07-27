###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1430_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-1430-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1430-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840991");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-30 11:08:59 +0530 (Mon, 30 Apr 2012)");
  script_cve_id("CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470",
                "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475",
                "CVE-2012-0477", "CVE-2012-0478", "CVE-2011-3062", "CVE-2011-1187",
                "CVE-2012-0479");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-1430-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1430-1");
  script_tag(name:"affected", value:"firefox on Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary Kwong,
  Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward, and Olli Pettay
  discovered memory safety issues affecting Firefox. If the user were tricked
  into opening a specially crafted page, an attacker could exploit these to
  cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2012-0467,
  CVE-2012-0468)

  Aki Helin discovered a use-after-free vulnerability in XPConnect. An
  attacker could potentially exploit this to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2012-0469)

  Atte Kettunen discovered that invalid frees cause heap corruption in
  gfxImageSurface. If a user were tricked into opening a malicious Scalable
  Vector Graphics (SVG) image file, an attacker could exploit these to cause
  a denial of service via application crash, or potentially execute code with
  the privileges of the user invoking Firefox. (CVE-2012-0470)

  Anne van Kesteren discovered a potential cross-site scripting (XSS)
  vulnerability via multibyte content processing errors. With cross-site
  scripting vulnerabilities, if a user were tricked into viewing a specially
  crafted page, a remote attacker could exploit this to modify the contents,
  or steal confidential data, within the same domain. (CVE-2012-0471)

  Matias Juntunen discovered a vulnerability in Firefox's WebGL
  implementation that potentially allows the reading of illegal video memory.
  An attacker could possibly exploit this to cause a denial of service via
  application crash. (CVE-2012-0473)

  Jordi Chancel, Eddy Bordi, and Chris McGowen discovered that Firefox
  allowed the address bar to display a different website than the one the
  user was visiting. This could potentially leave the user vulnerable to
  cross-site scripting (XSS) attacks. With cross-site scripting
  vulnerabilities, if a user were tricked into viewing a specially crafted
  page, a remote attacker could exploit this to modify the contents, or steal
  confidential data, within the same domain. (CVE-2012-0474)

  Simone Fabiano discovered that Firefox did not always send correct origin
  headers when connecting to an IPv6 websites. An attacker could potentially
  use this to bypass intended access controls. (CVE-2012-0475)

  Masato Kinugawa discovered that cross-site scripting (XSS) injection is
  possible during the decoding of ISO-2022-KR and ISO-2022-CN character sets.
  With cross-site scripting vulnerabilities, if a user were ...

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"12.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"12.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"12.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
