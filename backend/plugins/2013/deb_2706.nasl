# OpenVAS Vulnerability Test
# $Id: deb_2706.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2706-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892706");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-2865", "CVE-2013-2855", "CVE-2013-2861", "CVE-2013-2859", "CVE-2013-2856", "CVE-2013-2860", "CVE-2013-2862", "CVE-2013-2858", "CVE-2013-2863", "CVE-2013-2857");
  script_name("Debian Security Advisory DSA 2706-1 (chromium-browser - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-06-10 00:00:00 +0200 (Mon, 10 Jun 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2706.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 27.0.1453.110-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 27.0.1453.110-1.

For the unstable distribution (sid), these problems have been fixed in
version 27.0.1453.110-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Chromium web
browser.

CVE-2013-2855
The Developer Tools API in Chromium before 27.0.1453.110 allows
remote attackers to cause a denial of service (memory corruption) or
possibly have unspecified other impact via unknown vectors.

CVE-2013-2856
Use-after-free vulnerability in Chromium before 27.0.1453.110
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to the handling of
input.

CVE-2013-2857
Use-after-free vulnerability in Chromium before 27.0.1453.110
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to the handling of
images.

CVE-2013-2858
Use-after-free vulnerability in the HTML5 Audio implementation in
Chromium before 27.0.1453.110 allows remote attackers to cause
a denial of service or possibly have unspecified other impact via
unknown vectors.

CVE-2013-2859
Chromium before 27.0.1453.110 allows remote attackers to bypass
the Same Origin Policy and trigger namespace pollution via
unspecified vectors.

CVE-2013-2860
Use-after-free vulnerability in Chromium before 27.0.1453.110
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors involving access to a
database API by a worker process.

CVE-2013-2861
Use-after-free vulnerability in the SVG implementation in Chromium
before 27.0.1453.110 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
unknown vectors.

CVE-2013-2862
Skia, as used in Chromium before 27.0.1453.110, does not
properly handle GPU acceleration, which allows remote attackers to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via unknown vectors.

CVE-2013-2863
Chromium before 27.0.1453.110 does not properly handle SSL
sockets, which allows remote attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified
vectors.

CVE-2013-2865
Multiple unspecified vulnerabilities in Chromium before
27.0.1453.110 allow attackers to cause a denial of service or
possibly have other impact via unknown vectors.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"27.0.1453.110-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}