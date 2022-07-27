# OpenVAS Vulnerability Test
# $Id: deb_3443.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3443-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703443");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8540");
  script_name("Debian Security Advisory DSA 3443-1 (libpng - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-13 00:00:00 +0100 (Wed, 13 Jan 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3443.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"libpng on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.2.49-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 1.2.50-2+deb8u2.

We recommend that you upgrade your libpng packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in the libpng PNG library. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2015-8472It was discovered that the original fix for
CVE-2015-8126
was
incomplete and did not detect a potential overrun by applications
using png_set_PLTE directly. A remote attacker can take advantage of
this flaw to cause a denial of service (application crash).

CVE-2015-8540
Xiao Qixue and Chen Yu discovered a flaw in the png_check_keyword
function. A remote attacker can potentially take advantage of this
flaw to cause a denial of service (application crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpng12-0:amd64", ver:"1.2.49-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng12-0:i386", ver:"1.2.49-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.49-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.49-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng12-0:amd64", ver:"1.2.50-2+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng12-0:i386", ver:"1.2.50-2+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.50-2+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.50-2+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}