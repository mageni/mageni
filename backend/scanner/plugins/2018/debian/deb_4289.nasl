###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4289.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4289-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704289");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-1606", "CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16070",
                "CVE-2018-16071", "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076",
                "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080", "CVE-2018-16081",
                "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084", "CVE-2018-16085");
  script_name("Debian Security Advisory DSA 4289-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-07 00:00:00 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4289.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 69.0.3497.81-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-16065
Brendon Tiszka discovered an out-of-bounds write issue in the v8
javascript library.

CVE-2018-16066
cloudfuzzer discovered an out-of-bounds read issue in blink/webkit.

CVE-2018-16067
Zhe Jin discovered an out-of-bounds read issue in the WebAudio
implementation.

CVE-2018-16068
Mark Brand discovered an out-of-bounds write issue in the Mojo
message passing library.

CVE-2018-16069
Mark Brand discovered an out-of-bounds read issue in the swiftshader
library.

CVE-2018-16070
Ivan Fratric discovered an integer overflow issue in the skia library.

CVE-2018-16071
Natalie Silvanovich discovered a use-after-free issue in the WebRTC
implementation.

CVE-2018-16073
Jun Kokatsu discovered an error in the Site Isolation feature when
restoring browser tabs.

CVE-2018-16074
Jun Kokatsu discovered an error in the Site Isolation feature when
using a Blob URL.

CVE-2018-16075
Pepe Vila discovered an error that could allow remote sites to access
local files.

CVE-2018-16076
Aseksandar Nikolic discovered an out-of-bounds read issue in the pdfium
library.

CVE-2018-16077
Manuel Caballero discovered a way to bypass the Content Security Policy.

CVE-2018-16078
Cailan Sacks discovered that the Autofill feature could leak saved
credit card information.

CVE-2018-16079
Markus Vervier and Michele Orrù discovered a URL spoofing issue.

CVE-2018-16080
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-16081
Jann Horn discovered that local files could be accessed in the developer
tools.

CVE-2018-16082
Omair discovered a buffer overflow issue in the swiftshader library.

CVE-2018-16083
Natalie Silvanovich discovered an out-of-bounds read issue in the WebRTC
implementation.

CVE-2018-16084
Jun Kokatsu discovered a way to bypass a user confirmation dialog.

CVE-2018-16085
Roman Kuksin discovered a use-after-free issue.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-driver", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-shell", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-widevine", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}