###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1562.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1562-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891562");
  script_version("2019-03-25T09:51:34+0000");
  script_cve_id("CVE-2017-18267", "CVE-2018-10768", "CVE-2018-13988", "CVE-2018-16646");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1562-1] poppler security update)");
  script_tag(name:"last_modification", value:"2019-03-25 09:51:34 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-11-05 00:00:00 +0100 (Mon, 05 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"poppler on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.26.5-2+deb8u5.

We recommend that you upgrade your poppler packages.");
  script_tag(name:"summary", value:"Various security issues were discovered in the poppler PDF rendering
shared library.

CVE-2017-18267

The FoFiType1C::cvtGlyph function in fofi/FoFiType1C.cc in Poppler
through 0.64.0 allows remote attackers to cause a denial of service
(infinite recursion) via a crafted PDF file, as demonstrated by
pdftops.

The applied fix in FoFiType1C::cvtGlyph prevents infinite recursion
on such malformed documents.

CVE-2018-10768

A NULL pointer dereference in the AnnotPath::getCoordsLength function
in Annot.h in Poppler 0.24.5 had been discovered. A crafted input
will lead to a remote denial of service attack. Later versions of
Poppler such as 0.41.0 are not affected.

The applied patch fixes the crash on AnnotInk::draw for malformed
documents.

CVE-2018-13988

Poppler through 0.62 contains an out of bounds read vulnerability due
to an incorrect memory access that is not mapped in its memory space,
as demonstrated by pdfunite. This can result in memory corruption and
denial of service. This may be exploitable when a victim opens a
specially crafted PDF file.

The applied patch fixes crashes when Object has negative number.
(Specs say, number has to be > 0 and gen >= 0).

For Poppler in Debian jessie, the original upstream patch has been
backported to Poppler's old Object API.

CVE-2018-16646

In Poppler 0.68.0, the Parser::getObj() function in Parser.cc may
cause infinite recursion via a crafted file. A remote attacker can
leverage this for a DoS attack.

A range of upstream patches has been applied to Poppler's XRef.cc in
Debian jessie to consolidate a fix for this issue.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib-doc", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt5-dev", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler46", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.26.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
