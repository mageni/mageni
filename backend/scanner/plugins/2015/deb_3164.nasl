# OpenVAS Vulnerability Test
# $Id: deb_3164.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3164-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703164");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2047");
  script_name("Debian Security Advisory DSA 3164-1 (typo3-src - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-21 00:00:00 +0100 (Sat, 21 Feb 2015)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3164.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"typo3-src on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
this problem has been fixed in version 4.5.19+dfsg1-5+wheezy4.

The upcoming stable distribution (jessie) no longer includes Typo 3.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.40+dfsg1-1.

We recommend that you upgrade your typo3-src packages.");
  script_tag(name:"summary", value:"Pierrick Caillon discovered that the
authentication could be bypassed in the Typo 3 content management system.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}