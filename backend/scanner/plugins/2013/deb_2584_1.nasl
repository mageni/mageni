# OpenVAS Vulnerability Test
# $Id: deb_2584_1.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2584-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892584");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-5829", "CVE-2012-4201", "CVE-2012-5842", "CVE-2012-4216", "CVE-2012-4207");
  script_name("Debian Security Advisory DSA 2584-1 (iceape - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2012/dsa-2584.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"iceape on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 2.0.11-17.

For the testing distribution (wheezy), these problems have been fixed in
version 2.7.11-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.7.11-1.

We recommend that you upgrade your iceape packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in Iceape, the Debian Internet suite
based on Mozilla Seamonkey:

CVE-2012-5829Heap-based buffer overflow in the nsWindow::OnExposeEvent function could
allow remote attackers to execute arbitrary code.

CVE-2012-5842Multiple unspecified vulnerabilities in the browser engine could allow remote
attackers to cause a denial of service (memory corruption and application
crash) or possibly execute arbitrary code.

CVE-2012-4207The HZ-GB-2312 character-set implementation does not properly handle a ~
(tilde) character in proximity to a chunk delimiter, which allows remote
attackers to conduct cross-site scripting (XSS) attacks via a crafted
document.

CVE-2012-4201The evalInSandbox implementation uses an incorrect context during the
handling of JavaScript code that sets the location.href property, which
allows remote attackers to conduct cross-site scripting (XSS) attacks or read
arbitrary files by leveraging a sandboxed add-on.

CVE-2012-4216Use-after-free vulnerability in the gfxFont::GetFontEntry function allows
remote attackers to execute arbitrary code or cause a denial of service (heap
memory corruption) via unspecified vectors.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"iceape", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-browser", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-dev", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"2.0.11-17", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-browser", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-all", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-be", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-ca", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-cs", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-de", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-en-gb", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-es-ar", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-es-es", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-fi", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-fr", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-gl", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-hu", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-it", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-ja", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-lt", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-nb-no", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-nl", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-pl", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-pt-pt", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-ru", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-sk", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-sv-se", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-tr", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceape-l10n-zh-cn", ver:"2.7.11-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}