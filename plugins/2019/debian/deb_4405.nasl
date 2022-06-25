# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704405");
  script_version("$Revision: 14285 $");
  script_cve_id("CVE-2017-17480", "CVE-2018-14423", "CVE-2018-18088", "CVE-2018-5785", "CVE-2018-6616");
  script_name("Debian Security Advisory DSA 4405-1 (openjpeg2 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:08:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-10 00:00:00 +0100 (Sun, 10 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4405.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"openjpeg2 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.1.2-1.1+deb9u3.

We recommend that you upgrade your openjpeg2 packages.

For the detailed security status of openjpeg2 please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjpeg2");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in openjpeg2, the
open-source JPEG 2000 codec, that could be leveraged to cause a denial
of service or possibly remote code execution.

CVE-2017-17480
Write stack buffer overflow in the jp3d and jpwl codecs can result
in a denial of service or remote code execution via a crafted jp3d
or jpwl file.

CVE-2018-5785
Integer overflow can result in a denial of service via a crafted bmp
file.

CVE-2018-6616
Excessive iteration can result in a denial of service via a crafted
bmp file.

CVE-2018-14423
Division-by-zero vulnerabilities can result in a denial of service via
a crafted j2k file.

CVE-2018-18088
Null pointer dereference can result in a denial of service via a
crafted bmp file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjp2-7-dbg", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjp2-7-dev", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjp2-tools", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjp3d-tools", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpip-dec-server", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpip-server", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpip-viewer", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.2-1.1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}