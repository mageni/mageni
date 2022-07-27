# OpenVAS Vulnerability Test
# $Id: deb_3657.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3657-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703657");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920",
		  "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924",
		  "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930",
		  "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934",
  		  "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5844");
  script_name("Debian Security Advisory DSA 3657-1 (libarchive - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-07 10:08:38 +0530 (Wed, 07 Sep 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3657.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"libarchive on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these
    problems have been fixed in version 3.1.2-11+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 3.2.1-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.2.1-1.

We recommend that you upgrade your libarchive packages.");
  script_tag(name:"summary", value:"Hanno Boeck and Marcin Noga discovered multiple
    vulnerabilities in libarchive. Processing malformed archives may result in denial of
    service or the execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"bsdcpio", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bsdtar", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-dev:i386", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-dev:amd64", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-tools:i386", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-tools:amd64", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive13:i386", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive13:amd64", ver:"3.2.1-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bsdcpio", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bsdtar", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-dev:i386", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive-dev:amd64", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive13:i386", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarchive13:amd64", ver:"3.1.2-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}