# OpenVAS Vulnerability Test
# $Id: deb_3267.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3267-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703267");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254",
                  "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258",
                  "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1261", "CVE-2015-1262",
                  "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");
  script_name("Debian Security Advisory DSA 3267-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-22 00:00:00 +0200 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3267.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 43.0.2357.65-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 43.0.2357.65-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-1251
SkyLined discovered a use-after-free issue in speech
recognition.

CVE-2015-1252
An out-of-bounds write issue was discovered that could be used to
escape from the sandbox.

CVE-2015-1253
A cross-origin bypass issue was discovered in the DOM parser.

CVE-2015-1254
A cross-origin bypass issue was discovered in the DOM editing
feature.

CVE-2015-1255
Khalil Zhani discovered a use-after-free issue in WebAudio.

CVE-2015-1256
Atte Kettunen discovered a use-after-free issue in the SVG
implementation.

CVE-2015-1257
miaubiz discovered an overflow issue in the SVG implementation.

CVE-2015-1258
cloudfuzzer discovered an invalid size parameter used in the
libvpx library.

CVE-2015-1259
Atte Kettunen discovered an uninitialized memory issue in the
pdfium library.

CVE-2015-1260
Khalil Zhani discovered multiple use-after-free issues in chromium's
interface to the WebRTC library.

CVE-2015-1261
Juho Nurminen discovered a URL bar spoofing issue.

CVE-2015-1262
miaubiz discovered the use of an uninitialized class member in
font handling.

CVE-2015-1263
Mike Ruddy discovered that downloading the spellcheck dictionary
was not done over HTTPS.

CVE-2015-1264
K0r3Ph1L discovered a cross-site scripting issue that could be
triggered by bookmarking a site.

CVE-2015-1265
The chrome 43 development team found and fixed various issues
during internal auditing. Also multiple issues were fixed in
the libv8 library, version 4.3.61.21.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}