###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4256.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4256-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704256");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152",
                "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157",
                "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163",
                "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168",
                "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173",
                "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178",
                "CVE-2018-6179");
  script_name("Debian Security Advisory DSA 4256-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-26 00:00:00 +0200 (Thu, 26 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4256.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 68.0.3440.75-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-4117
AhsanEjaz discovered an information leak.

CVE-2018-6044
Rob Wu discovered a way to escalate privileges using extensions.

CVE-2018-6150
Rob Wu discovered an information disclosure issue (this problem was
fixed in a previous release but was mistakenly omitted from upstream's
announcement at the time).

CVE-2018-6151
Rob Wu discovered an issue in the developer tools (this problem was
fixed in a previous release but was mistakenly omitted from upstream's
announcement at the time).

CVE-2018-6152
Rob Wu discovered an issue in the developer tools (this problem was
fixed in a previous release but was mistakenly omitted from upstream's
announcement at the time).

CVE-2018-6153
Zhen Zhou discovered a buffer overflow issue in the skia library.

CVE-2018-6154
Omair discovered a buffer overflow issue in the WebGL implementation.

CVE-2018-6155
Natalie Silvanovich discovered a use-after-free issue in the WebRTC
implementation.

CVE-2018-6156
Natalie Silvanovich discovered a buffer overflow issue in the WebRTC
implementation.

CVE-2018-6157
Natalie Silvanovich discovered a type confusion issue in the WebRTC
implementation.

CVE-2018-6158
Zhe Jin discovered a use-after-free issue.

CVE-2018-6159
Jun Kokatsu discovered a way to bypass the same origin policy.

CVE-2018-6161
Jun Kokatsu discovered a way to bypass the same origin policy.

CVE-2018-6162
Omair discovered a buffer overflow issue in the WebGL implementation.

CVE-2018-6163
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6164
Jun Kokatsu discovered a way to bypass the same origin policy.

CVE-2018-6165
evil1m0 discovered a URL spoofing issue.

CVE-2018-6166
Lynas Zhang discovered a URL spoofing issue.

CVE-2018-6167
Lynas Zhang discovered a URL spoofing issue.

CVE-2018-6168
Gunes Acar and Danny Y. Huang discovered a way to bypass the Cross
Origin Resource Sharing policy.

CVE-2018-6169
Sam P discovered a way to bypass permissions when installing
extensions.

CVE-2018-6170
A type confusion issue was discovered in the pdfium library.

CVE-2018-6171
A use-after-free issue was discovered in the WebBluetooth
implementation.

CVE-2018-6172
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6173
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6174
Mark Brand discovered an integer overflow issue in the swiftshader
library.

CVE-2018-6175
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6176
Jann Horn discovered a way to escalate privileges using extensions.

CVE-2018-6177
Ron Masas discovered an information leak.

CVE-2018-6178
Khalil Zhani discovered a user interface spoofing issue.

CVE-2018-6179
It was discovered that information about files local to the system
could be leaked to extensions.

This version also fixes a regression introduced in the previous security
update that could prevent decoding of particular audio/video codecs.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-driver", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-shell", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-widevine", ver:"68.0.3440.75-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}