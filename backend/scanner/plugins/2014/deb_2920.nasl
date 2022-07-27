# OpenVAS Vulnerability Test
# $Id: deb_2920.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2920-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702920");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733", "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1736");
  script_name("Debian Security Advisory DSA 2920-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-03 00:00:00 +0200 (Sat, 03 May 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2920.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 34.0.1847.132-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 34.0.1847.132-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2014-1730
A type confusion issue was discovered in the v8 javascript library.

CVE-2014-1731
John Butler discovered a type confusion issue in the WebKit/Blink
document object model implementation.

CVE-2014-1732
Khalil Zhani discovered a use-after-free issue in the speech
recognition feature.

CVE-2014-1733
Jed Davis discovered a way to bypass the seccomp-bpf sandbox.

CVE-2014-1734
The Google Chrome development team discovered and fixed multiple
issues with potential security impact.

CVE-2014-1735
The Google Chrome development team discovered and fixed multiple
issues in version 3.24.35.33 of the v8 javascript library.

CVE-2014-1736
SkyLined discovered an integer overflow issue in the v8 javascript
library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"34.0.1847.132-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}