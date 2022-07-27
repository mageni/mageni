# OpenVAS Vulnerability Test
# $Id: deb_3716.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3716-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703716");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9074");
  script_name("Debian Security Advisory DSA 3716-1 (firefox-esr - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-16 00:00:00 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3716.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"firefox-esr on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 45.5.0esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 45.5.0esr-1 and version 50.0-1 of the firefox source package.

We recommend that you upgrade your firefox-esr packages.");
  script_tag(name:"summary", value:"Multiple security issues have been found in the Mozilla Firefox web
browser: Multiple memory safety errors, buffer overflows and other
implementation errors may lead to the execution of arbitrary code or
bypass of the same-origin policy. Also, a man-in-the-middle attack in
the addon update mechanism has been fixed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"firefox-esr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-dbg", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-dev", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-as", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-be", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-bd", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-en-za", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-mai", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ml", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-or", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dev", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"45.5.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}