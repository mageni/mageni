# OpenVAS Vulnerability Test
# $Id: deb_3376.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3376-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703376");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2015-1303", "CVE-2015-1304", "CVE-2015-6755", "CVE-2015-6756",
                  "CVE-2015-6757", "CVE-2015-6758", "CVE-2015-6759", "CVE-2015-6760",
                  "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763");
  script_name("Debian Security Advisory DSA 3376-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-20 00:00:00 +0200 (Tue, 20 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3376.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 46.0.2490.71-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 46.0.2490.71-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2015-1303
Mariusz Mlynski discovered a way to bypass the Same Origin Policy
in the DOM implementation.

CVE-2015-1304
Mariusz Mlynski discovered a way to bypass the Same Origin Policy
in the v8 javascript library.

CVE-2015-6755
Mariusz Mlynski discovered a way to bypass the Same Origin Policy
in blink/webkit.

CVE-2015-6756
A use-after-free issue was found in the pdfium library.

CVE-2015-6757
Collin Payne found a use-after-free issue in the ServiceWorker
implementation.

CVE-2015-6758
Atte Kettunen found an issue in the pdfium library.

CVE-2015-6759
Muneaki Nishimura discovered an information leak.

CVE-2015-6760
Ronald Crane discovered a logic error in the ANGLE library
involving lost device events.

CVE-2015-6761
Aki Helin and Khalil Zhani discovered a memory corruption issue in
the ffmpeg library.

CVE-2015-6762
Muneaki Nishimura discovered a way to bypass the Same Origin Policy
in the CSS implementation.

CVE-2015-6763
The chrome 46 development team found and fixed various issues
during internal auditing. Also multiple issues were fixed in
the v8 javascript library, version 4.6.85.23.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"46.0.2490.71-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"46.0.2490.71-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"46.0.2490.71-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"46.0.2490.71-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromedriver", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}