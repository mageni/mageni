# OpenVAS Vulnerability Test
# $Id: deb_3830.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3830-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703830");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2017-7867", "CVE-2017-7868");
  script_name("Debian Security Advisory DSA 3830-1 (icu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-19 00:00:00 +0200 (Wed, 19 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3830.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"icu on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 52.1-8+deb8u5.

For the upcoming stable (stretch) and unstable (sid) distributions,
these problems have been fixed in version 57.1-6.

We recommend that you upgrade your icu packages.");
  script_tag(name:"summary", value:"It was discovered that icu, the International Components for Unicode
library, did not correctly validate its input. An attacker could use
this problem to trigger an out-of-bound write through a heap-based
buffer overflow, thus causing a denial of service via application
crash, or potential execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icu-devtools", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icu-devtools-dbg", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icu-doc", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu57:amd64", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu57:i386", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu57-dbg", ver:"57.1-6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icu-devtools", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icu-doc", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev:i386", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev:amd64", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu52:i386", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu52:amd64", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu52-dbg", ver:"52.1-8+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}