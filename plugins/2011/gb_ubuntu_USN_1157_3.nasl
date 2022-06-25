###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1157_3.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-1157-3
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1157-3/");
  script_oid("1.3.6.1.4.1.25623.1.0.840690");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371", "CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2370", "CVE-2011-2369");
  script_name("Ubuntu Update for firefox USN-1157-3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1157-3");
  script_tag(name:"affected", value:"firefox on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1157-1 fixed vulnerabilities in Firefox. Unfortunately, this update
  produced the side effect of pulling in Firefox on some systems that did not
  have it installed during a dist-upgrade due to changes in the Ubuntu
  language packs. This update fixes the problem. We apologize for the
  inconvenience.

  Original advisory details:

  Bob Clary, Kevin Brosnan, Gary Kwong, Jesse Ruderman, Christian Biesinger,
  Bas Schouten, Igor Bukanov, Bill McCloskey, Olli Pettay, Daniel Veditz and
  Marcia Knous discovered multiple memory vulnerabilities in the browser
  rendering engine. An attacker could possibly execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2374, CVE-2011-2375)

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

  It was discovered that Firefox's WebGL textures did not honor same-origin
  policy. If a user were tricked into viewing a malicious site, an attacker
  could potentially view image data from a different site. (CVE-2011-2366)

  Christoph Diehl discovered an out-of-bounds read vulnerability in WebGL
  code. An attacker could potentially read data that other processes had
  stored in the GPU. (CVE-2011-2367)

  Christoph Diehl discovered an invalid write vulnerability in WebGL code. An
  attacker could potentially use this to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2011-2368)

  It was discovered that an unauthorized site could trigger an installation
  dialog for addons and themes. If a user were tricked into viewing a
  malicious site, an attacker could possibly trick the user into installing a
  malicious addon or theme. (CVE-2011-2370)

  Mario Heiderich discovered a vulnerability in displaying decoded
  HTML-encoded entities inside SVG elements. An attacker could utilize this
  to perform cross-site scripting attacks. (CVE-2011-2369)");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox-locale-af", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ar", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-as", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ast", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-be", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-bg", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-bn", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-br", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-bs", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ca", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-cs", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-cy", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-da", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-de", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-el", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-en", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-eo", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-es", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-et", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-eu", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-fa", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-fi", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-fr", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-fy", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ga", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-gd", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-gl", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-gu", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-he", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-hi", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-hr", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-hu", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-hy", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-id", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-is", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-it", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ja", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ka", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-kk", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-kn", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ko", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ku", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-lg", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-lt", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-lv", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-mai", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-mk", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ml", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-mr", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-nb", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-nl", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-nn", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-nso", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-oc", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-or", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-pa", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-pl", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-pt", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ro", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ru", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-si", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-sk", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-sl", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-sq", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-sr", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-sv", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-ta", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-te", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-th", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-tr", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-uk", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-vi", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-zh-hans", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-zh-hant", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-locale-zu", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
