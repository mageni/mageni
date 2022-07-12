# OpenVAS Vulnerability Test
# $Id: deb_3315.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3315-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703315");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2015-1263", "CVE-2015-1266", "CVE-2015-1267", "CVE-2015-1268",
                  "CVE-2015-1269", "CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272",
                  "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1276", "CVE-2015-1277",
                  "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281",
                  "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285",
                  "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289");
  script_name("Debian Security Advisory DSA 3315-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-23 00:00:00 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3315.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 44.0.2403.89-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 44.0.2403.89-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-1266
Intended access restrictions could be bypassed for certain URLs like
chrome://gpu.

CVE-2015-1267
A way to bypass the Same Origin Policy was discovered.

CVE-2015-1268
Mariusz Mlynski also discovered a way to bypass the Same Origin Policy.

CVE-2015-1269
Mike Rudy discovered that hostnames were not properly compared in the
HTTP Strict Transport Policy and HTTP Public Key Pinning features,
which could allow those access restrictions to be bypassed.

CVE-2015-1270
Atte Kettunen discovered an uninitialized memory read in the ICU library.

CVE-2015-1271
cloudfuzzer discovered a buffer overflow in the pdfium library.

CVE-2015-1272
Chamal de Silva discovered race conditions in the GPU process
implementation.

CVE-2015-1273
makosoft discovered a buffer overflow in openjpeg, which is used by
the pdfium library embedded in chromium.

CVE-2015-1274
andrewm.bpi discovered that the auto-open list allowed certain file
types to be executed immediately after download.

CVE-2015-1276
Colin Payne discovered a use-after-free issue in the IndexedDB
implementation.

CVE-2015-1277
SkyLined discovered a use-after-free issue in chromium's accessibility
implementation.

CVE-2015-1278
Chamal de Silva discovered a way to use PDF documents to spoof a URL.

CVE-2015-1279
mlafon discovered a buffer overflow in the pdfium library.

CVE-2015-1280
cloudfuzzer discovered a memory corruption issue in the SKIA library.

CVE-2015-1281
Masato Knugawa discovered a way to bypass the Content Security
Policy.

CVE-2015-1282
Chamal de Silva discovered multiple use-after-free issues in the
pdfium library.

CVE-2015-1283
Huzaifa Sidhpurwala discovered a buffer overflow in the expat
library.

CVE-2015-1284
Atte Kettunen discovered that the maximum number of page frames
was not correctly checked.

CVE-2015-1285
gazheyes discovered an information leak in the XSS auditor,
which normally helps to prevent certain classes of cross-site
scripting problems.

CVE-2015-1286
A cross-site scripting issue was discovered in the interface to
the v8 javascript library.

CVE-2015-1287
filedescriptor discovered a way to bypass the Same Origin Policy.

CVE-2015-1288Mike Ruddy discovered that the spellchecking dictionaries could
still be downloaded over plain HTTP (related to CVE-2015-1263
).

CVE-2015-1289
The chrome 44 development team found and fixed various issues
during internal auditing.

In addition to the above issues, Google disabled the hotword extension
by default in this version, which if enabled downloads files without
the user's intervention.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"44.0.2403.89-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"44.0.2403.89-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"44.0.2403.89-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"44.0.2403.89-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"44.0.2403.89-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}