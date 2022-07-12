# OpenVAS Vulnerability Test
# $Id: deb_3762.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3762-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703762");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-3622",
                  "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3945", "CVE-2016-3990",
                  "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316",
                  "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322",
                  "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-6223",
                  "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453",
                  "CVE-2016-9532", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535",
                  "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9540");
  script_name("Debian Security Advisory DSA 3762-1 (tiff - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-13 00:00:00 +0100 (Fri, 13 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3762.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"tiff on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 4.0.3-12.3+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 4.0.7-4.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.7-4.

We recommend that you upgrade your tiff packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in the libtiff library and the included tools tiff2rgba, rgb2ycbcr,
tiffcp, tiffcrop, tiff2pdf and tiffsplit, which may result in denial of service,
memory disclosure or the execution of arbitrary code.

There were additional vulnerabilities in the tools bmp2tiff, gif2tiff,
thumbnail and ras2tiff, but since these were addressed by the libtiff
developers by removing the tools altogether, no patches are available
and those tools were also removed from the tiff package in Debian
stable. The change had already been made in Debian stretch before and
no applications included in Debian are known to rely on these scripts.
If you use those tools in custom setups, consider using a different
conversion/thumbnailing tool.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5:amd64", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libtiff5-dev:amd64", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-dev:i386", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.3-12.3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5:amd64", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libtiff5-dev:amd64", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-dev:i386", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.7-4", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}