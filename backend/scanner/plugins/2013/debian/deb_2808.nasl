# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2808-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702808");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2013-6052", "CVE-2013-6054", "CVE-2013-6045", "CVE-2013-1447");
  script_name("Debian Security Advisory DSA 2808-1 (openjpeg - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2013-12-03 00:00:00 +0100 (Tue, 03 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2808.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"openjpeg on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 1.3+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 1.3+dfsg-4.7.

For the testing distribution (jessie), and the unstable distribution (sid),
these problems will be fixed soon.

We recommend that you upgrade your openjpeg packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in OpenJPEG, a JPEG 2000
image library, that may lead to denial of service (CVE-2013-1447) via
application crash or high memory consumption, possible code execution
through heap buffer overflows (CVE-2013-6045), information disclosure
(CVE-2013-6052), or yet another heap buffer overflow that only appears
to affect OpenJPEG 1.3 (CVE-2013-6054
).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4.7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4.7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4.7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4.7", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
