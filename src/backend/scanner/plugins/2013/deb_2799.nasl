# OpenVAS Vulnerability Test
# $Id: deb_2799.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2799-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892799");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-6626", "CVE-2013-6623", "CVE-2013-6631", "CVE-2013-6625", "CVE-2013-6624", "CVE-2013-6630", "CVE-2013-6632", "CVE-2013-6629", "CVE-2013-6628", "CVE-2013-2931", "CVE-2013-6627", "CVE-2013-6621", "CVE-2013-6622");
  script_name("Debian Security Advisory DSA 2799-1 (chromium-browser - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-11-16 00:00:00 +0100 (Sat, 16 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2799.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 31.0.1650.57-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 31.0.1650.57-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-2931
The chrome 31 development team found various issues from internal
fuzzing, audits, and other studies.

CVE-2013-6621
Khalil Zhani discovered a use-after-free issue in speech input
handling.

CVE-2013-6622cloudfuzzer
discovered a use-after-free issue in
HTMLMediaElement.

CVE-2013-6623miaubiz
discovered an out-of-bounds read in the Blink/Webkit SVG
implementation.

CVE-2013-6624
Jon Butler discovered a use-after-free issue in id attribute
strings.

CVE-2013-6625cloudfuzzer
discovered a use-after-free issue in the Blink/Webkit
DOM implementation.

CVE-2013-6626
Chamal de Silva discovered an address bar spoofing issue.

CVE-2013-6627skylined
discovered an out-of-bounds read in the HTTP stream
parser.

CVE-2013-6628
Antoine Delignat-Lavaud and Karthikeyan Bhargavan of INRIA Paris
discovered that a different (unverified) certificate could be used
after successful TLS renegotiation with a valid certificate.

CVE-2013-6629
Michal Zalewski discovered an uninitialized memory read in the
libjpeg and libjpeg-turbo libraries.

CVE-2013-6630
Michal Zalewski discovered another uninitialized memory read in
the libjpeg and libjpeg-turbo libraries.

CVE-2013-6631
Patrik Höglund discovered a use-free issue in the libjingle
library.

CVE-2013-6632
Pinkie Pie discovered multiple memory corruption issues.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}