###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4237.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4237-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.704237");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-6118", "CVE-2018-6120", "CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6123",
                "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6129",
                "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134",
                "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139",
                "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144",
                "CVE-2018-6145", "CVE-2018-6147", "CVE-2018-6148", "CVE-2018-6149");
  script_name("Debian Security Advisory DSA 4237-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-30 00:00:00 +0200 (Sat, 30 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4237.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 67.0.3396.87-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-6118
Ned Williamson discovered a use-after-free issue.

CVE-2018-6120
Zhou Aiting discovered a buffer overflow issue in the pdfium library.

CVE-2018-6121
It was discovered that malicious extensions could escalate privileges.

CVE-2018-6122
A type confusion issue was discovered in the v8 javascript library.

CVE-2018-6123
Looben Yang discovered a use-after-free issue.

CVE-2018-6124
Guang Gong discovered a type confusion issue.

CVE-2018-6125
Yubico discovered that the WebUSB implementation was too permissive.

CVE-2018-6126
Ivan Fratric discovered a buffer overflow issue in the skia library.

CVE-2018-6127
Looben Yang discovered a use-after-free issue.

CVE-2018-6129
Natalie Silvanovich discovered an out-of-bounds read issue in WebRTC.

CVE-2018-6130
Natalie Silvanovich discovered an out-of-bounds read issue in WebRTC.

CVE-2018-6131
Natalie Silvanovich discovered an error in WebAssembly.

CVE-2018-6132
Ronald E. Crane discovered an uninitialized memory issue.

CVE-2018-6133
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6134
Jun Kokatsu discovered a way to bypass the Referrer Policy.

CVE-2018-6135
Jasper Rebane discovered a user interface spoofing issue.

CVE-2018-6136
Peter Wong discovered an out-of-bounds read issue in the v8 javascript
library.

CVE-2018-6137
Michael Smith discovered an information leak.

CVE-2018-6138
François Lajeunesse-Robert discovered that the extensions policy was
too permissive.

CVE-2018-6139
Rob Wu discovered a way to bypass restrictions in the debugger extension.

CVE-2018-6140
Rob Wu discovered a way to bypass restrictions in the debugger extension.

CVE-2018-6141
Yangkang discovered a buffer overflow issue in the skia library.

CVE-2018-6142
Choongwoo Han discovered an out-of-bounds read in the v8 javascript
library.

CVE-2018-6143
Guang Gong discovered an out-of-bounds read in the v8 javascript library.

CVE-2018-6144
pdknsk discovered an out-of-bounds read in the pdfium library.

CVE-2018-6145
Masato Kinugawa discovered an error in the MathML implementation.

CVE-2018-6147
Michail Pishchagin discovered an error in password entry fields.

CVE-2018-6148
Micha? Bentkowski discovered that the Content Security Policy header
was handled incorrectly.

CVE-2018-6149
Yu Zhou and Jundong Xie discovered an out-of-bounds write issue in the
v8 javascript library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-driver", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-shell", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-widevine", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}