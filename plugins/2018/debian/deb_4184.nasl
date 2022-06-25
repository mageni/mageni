###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4184.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4184-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704184");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448",
                "CVE-2017-14450", "CVE-2017-2887", "CVE-2018-3837", "CVE-2018-3838", "CVE-2018-3839");
  script_name("Debian Security Advisory DSA 4184-1 (sdl-image1.2 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-28 00:00:00 +0200 (Sat, 28 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4184.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"sdl-image1.2 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.2.12-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1.2.12-5+deb9u1.

We recommend that you upgrade your sdl-image1.2 packages.

For the detailed security status of sdl-image1.2 please refer to its
security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sdl-image1.2");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the image loading
library for Simple DirectMedia Layer 1.2, which could result in denial
of service or the execution of arbitrary code if malformed image files
are opened.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.12-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsdl-image1.2-dbg", ver:"1.2.12-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.12-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.12-5+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsdl-image1.2-dbg", ver:"1.2.12-5+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.12-5+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}