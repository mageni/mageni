# OpenVAS Vulnerability Test
# $Id: deb_2785.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2785-1 using nvtgen 1.0
# Script version: 1.1
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
  script_oid("1.3.6.1.4.1.25623.1.0.892794");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-2906", "CVE-2013-2927", "CVE-2013-2913", "CVE-2013-2915", "CVE-2013-2912", "CVE-2013-2928", "CVE-2013-2920", "CVE-2013-2919", "CVE-2013-2917", "CVE-2013-2910", "CVE-2013-2908", "CVE-2013-2925", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2918", "CVE-2013-2924", "CVE-2013-2926", "CVE-2013-2921", "CVE-2013-2907", "CVE-2013-2916", "CVE-2013-2909", "CVE-2013-2911");
  script_name("Debian Security Advisory DSA 2785-1 (chromium-browser - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-10-26 00:00:00 +0200 (Sat, 26 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2785.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 30.0.1599.101-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 30.0.1599.101-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-2906
Atte Kettunen of OUSPG discovered race conditions in Web Audio.

CVE-2013-2907
Boris Zbarsky discovered an out-of-bounds read in window.prototype.

CVE-2013-2908
Chamal de Silva discovered an address bar spoofing issue.

CVE-2013-2909
Atte Kuttenen of OUSPG discovered a use-after-free issue in
inline-block.

CVE-2013-2910
Byoungyoung Lee of the Georgia Tech Information Security Center
discovered a use-after-free issue in Web Audio.

CVE-2013-2911
Atte Kettunen of OUSPG discovered a use-after-free in Blink's XSLT
handling.

CVE-2013-2912
Chamal de Silva and 41.w4r10r(at)garage4hackers.com discovered a
use-after-free issue in the Pepper Plug-in API.

CVE-2013-2913
cloudfuzzer discovered a use-after-free issue in Blink's XML
document parsing.

CVE-2013-2915
Wander Groeneveld discovered an address bar spoofing issue.

CVE-2013-2916
Masato Kinugawa discovered an address bar spoofing issue.

CVE-2013-2917
Byoungyoung Lee and Tielei Wang discovered an out-of-bounds read
issue in Web Audio.

CVE-2013-2918
Byoungyoung Lee discoverd an out-of-bounds read in Blink's DOM
implementation.

CVE-2013-2919
Adam Haile of Concrete Data discovered a memory corruption issue
in the V8 javascript library.

CVE-2013-2920
Atte Kuttunen of OUSPG discovered an out-of-bounds read in URL
host resolving.

CVE-2013-2921
Byoungyoung Lee and Tielei Wang discovered a use-after-free issue
in resource loading.

CVE-2013-2922
Jon Butler discovered a use-after-free issue in Blink's HTML
template element implementation.

CVE-2013-2924
A use-after-free issue was discovered in the International
Components for Unicode (ICU) library.

CVE-2013-2925
Atte Kettunen of OUSPG discover a use-after-free issue in Blink's
XML HTTP request implementation.

CVE-2013-2926
cloudfuzzer discovered a use-after-free issue in the list indenting
implementation.

CVE-2013-2927
cloudfuzzer discovered a use-after-free issue in the HTML form
submission implementation.

CVE-2013-2923 and CVE-2013-2928
The chrome 30 development team found various issues from internal
fuzzing, audits, and other studies.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}