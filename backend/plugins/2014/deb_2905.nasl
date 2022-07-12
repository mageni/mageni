# OpenVAS Vulnerability Test
# $Id: deb_2905.nasl 14277 2019-03-18 14:45:38Z cfischer $
# Auto-generated from advisory DSA 2905-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702905");
  script_version("$Revision: 14277 $");
  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719",
                  "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723",
                  "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727",
                  "CVE-2014-1728", "CVE-2014-1729");
  script_name("Debian Security Advisory DSA 2905-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-15 00:00:00 +0200 (Tue, 15 Apr 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2905.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 34.0.1847.116-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 34.0.1847.116-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were
discovered in the chromium web browser.

CVE-2014-1716
A cross-site scripting issue was discovered in the v8 javascript
library.

CVE-2014-1717
An out-of-bounds read issue was discovered in the v8 javascript
library.

CVE-2014-1718
Aaron Staple discovered an integer overflow issue in chromium's
software compositor.

CVE-2014-1719
Colin Payne discovered a use-after-free issue in the web workers
implementation.

CVE-2014-1720
cloudfuzzer discovered a use-after-free issue in the Blink/Webkit
document object model implementation.

CVE-2014-1721
Christian Holler discovered a memory corruption issue in the v8
javascript library.

CVE-2014-1722
miaubiz discovered a use-after-free issue in block rendering.

CVE-2014-1723
George McBay discovered a url spoofing issue.

CVE-2014-1724
Atte Kettunen discovered a use-after-free issue in freebsoft's
libspeechd library.

Because of this issue, the text-to-speech feature is now disabled
by default ('--enable-speech-dispatcher' at the command-line can
re-enable it).

CVE-2014-1725
An out-of-bounds read was discovered in the base64 implementation.

CVE-2014-1726
Jann Horn discovered a way to bypass the same origin policy.

CVE-2014-1727
Khalil Zhani discovered a use-after-free issue in the web color
chooser implementation.

CVE-2014-1728
The Google Chrome development team discovered and fixed multiple
issues with potential security impact.

CVE-2014-1729
The Google Chrome development team discovered and fixed multiple
issues in version 3.24.35.22 of the v8 javascript library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}