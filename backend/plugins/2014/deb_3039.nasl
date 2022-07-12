# OpenVAS Vulnerability Test
# $Id: deb_3039.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3039-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703039");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167", "CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177", "CVE-2014-3178", "CVE-2014-3179");
  script_name("Debian Security Advisory DSA 3039-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-01 16:58:59 +0530 (Wed, 01 Oct 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3039.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 37.0.2062.120-1~deb7u1.

For the testing (jessie) and unstable (sid) distributions, these
problems have been fixed in version 37.0.2062.120-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2014-3160
Christian Schneider discovered a same origin bypass issue in SVG
file resource fetching.

CVE-2014-3162
The Google Chrome development team addressed multiple issues with
potential security impact for chromium 36.0.1985.125.

CVE-2014-3165
Colin Payne discovered a use-after-free issue in the Web Sockets
implementation.

CVE-2014-3166
Antoine Delignat-Lavaud discovered an information leak in the SPDY
protocol implementation.

CVE-2014-3167
The Google Chrome development team addressed multiple issues with
potential security impact for chromium 36.0.1985.143.

CVE-2014-3168
cloudfuzzer discovered a use-after-free issue in SVG image file
handling.

CVE-2014-3169
Andrzej Dyjak discovered a use-after-free issue in the Webkit/Blink
Document Object Model implementation.

CVE-2014-3170
Rob Wu discovered a way to spoof the url of chromium extensions.

CVE-2014-3171
cloudfuzzer discovered a use-after-free issue in chromium's v8
bindings.

CVE-2014-3172
Eli Grey discovered a way to bypass access restrictions using
chromium's Debugger extension API.

CVE-2014-3173
jmuizelaar discovered an uninitialized read issue in WebGL.

CVE-2014-3174
Atte Kettunen discovered an uninitialized read issue in Web Audio.

CVE-2014-3175
The Google Chrome development team addressed multiple issues with
potential security impact for chromium 37.0.2062.94.

CVE-2014-3176
lokihardt@asrt discovered a combination of flaws that can lead to
remote code execution outside of chromium's sandbox.

CVE-2014-3177
lokihardt@asrt discovered a combination of flaws that can lead to
remote code execution outside of chromium's sandbox.

CVE-2014-3178
miaubiz discovered a use-after-free issue in the Document Object
Model implementation in Blink/Webkit.

CVE-2014-3179
The Google Chrome development team addressed multiple issues with
potential security impact for chromium 37.0.2062.120.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}