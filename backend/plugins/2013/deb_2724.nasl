# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2724-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892724");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2013-2877", "CVE-2013-2871", "CVE-2013-2853", "CVE-2013-2876", "CVE-2013-2867", "CVE-2013-2875", "CVE-2013-2870", "CVE-2013-2868", "CVE-2013-2879", "CVE-2013-2878", "CVE-2013-2880", "CVE-2013-2869", "CVE-2013-2873");
  script_name("Debian Security Advisory DSA 2724-1 (chromium-browser - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2013-07-17 00:00:00 +0200 (Wed, 17 Jul 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2724.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 28.0.1500.71-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 28.0.1500.71-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Chromium web browser.

CVE-2013-2853
The HTTPS implementation does not ensure that headers are terminated
by \r\n\r\n (carriage return, newline, carriage return, newline).

CVE-2013-2867
Chrome does not properly prevent pop-under windows.

CVE-2013-2868
common/extensions/sync_helper.cc proceeds with sync operations for
NPAPI extensions without checking for a certain plugin permission
setting.

CVE-2013-2869
Denial of service (out-of-bounds read) via a crafted JPEG2000
image.

CVE-2013-2870
Use-after-free vulnerability in network sockets.

CVE-2013-2871
Use-after-free vulnerability in input handling.

CVE-2013-2873
Use-after-free vulnerability in resource loading.

CVE-2013-2875
Out-of-bounds read in SVG file handling.

CVE-2013-2876
Chromium does not properly enforce restrictions on the capture of
screenshots by extensions, which could lead to information
disclosure from previous page visits.

CVE-2013-2877
Out-of-bounds read in XML file handling.

CVE-2013-2878
Out-of-bounds read in text handling.

CVE-2013-2879
The circumstances in which a renderer process can be considered a
trusted process for sign-in and subsequent sync operations were
not properly checked.

CVE-2013-2880
The Chromium 28 development team found various issues from internal
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
if((res = isdpkgvuln(pkg:"chromium", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"28.0.1500.71-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}