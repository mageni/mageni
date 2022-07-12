# OpenVAS Vulnerability Test
# $Id: deb_3238.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3238-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703238");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238",
                  "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244",
                  "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248",
                  "CVE-2015-1249", "CVE-2015-3333", "CVE-2015-3334", "CVE-2015-3336");
  script_name("Debian Security Advisory DSA 3238-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-26 00:00:00 +0200 (Sun, 26 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3238.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 42.0.2311.90-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems
have been fixed in version 42.0.2311.90-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-1235
A Same Origin Policy bypass issue was discovered in the HTML
parser.

CVE-2015-1236
Amitay Dobo discovered a Same Origin Policy bypass in the Web Audio
API.

CVE-2015-1237
Khalil Zhani discovered a use-after-free issue in IPC.

CVE-2015-1238cloudfuzzer
discovered an out-of-bounds write in the skia
library.

CVE-2015-1240w3bd3vil
discovered an out-of-bounds read in the WebGL
implementation.

CVE-2015-1241
Phillip Moon and Matt Weston discovered a way to trigger local user
interface actions remotely via a crafted website.

CVE-2015-1242
A type confusion issue was discovered in the v8 javascript
library.

CVE-2015-1244
Mike Ruddy discovered a way to bypass the HTTP Strict Transport Security
policy.

CVE-2015-1245
Khalil Zhani discovered a use-after-free issue in the pdfium
library.

CVE-2015-1246
Atte Kettunen discovered an out-of-bounds read issue in
webkit/blink.

CVE-2015-1247Jann Horn discovered that file:
URLs in OpenSearch documents were not
sanitized, which could allow local files to be read remotely when using
the OpenSearch feature from a crafted website.

CVE-2015-1248
Vittorio Gambaletta discovered a way to bypass the SafeBrowsing feature,
which could allow the remote execution of a downloaded executable
file.

CVE-2015-1249
The chrome 41 development team found various issues from internal
fuzzing, audits, and other studies.

CVE-2015-3333
Multiple issues were discovered and fixed in v8 4.2.7.14.

CVE-2015-3334
It was discovered that remote websites could capture video data from
attached web cameras without permission.

CVE-2015-3336
It was discovered that remote websites could cause user interface
disruptions like window fullscreening and mouse pointer locking.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"42.0.2311.90-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"42.0.2311.90-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"42.0.2311.90-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"42.0.2311.90-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromedriver", ver:"42.0.2311.90-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"42.0.2311.90-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"42.0.2311.90-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"42.0.2311.90-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"42.0.2311.90-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}