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
  script_oid("1.3.6.1.4.1.25623.1.0.891706");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2018-19058", "CVE-2018-20481", "CVE-2018-20662", "CVE-2019-7310", "CVE-2019-9200");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1706-1] poppler security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-09 00:00:00 +0100 (Sat, 09 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00008.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"poppler on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.26.5-2+deb8u8.

We recommend that you upgrade your poppler packages.");
  script_tag(name:"summary", value:"Several security vulnerabilities were discovered in the poppler PDF
rendering shared library.

CVE-2018-19058

A reachable abort in Object.h will lead to denial-of-service because
EmbFile::save2 in FileSpec.cc lacks a stream check before saving an
embedded file.

CVE-2018-20481

Poppler mishandles unallocated XRef entries, which allows remote
attackers to cause a denial-of-service (NULL pointer dereference)
via a crafted PDF document.

CVE-2018-20662

Poppler allows attackers to cause a denial-of-service (application
crash and segmentation fault by crafting a PDF file in which an xref
data structure is corrupted.

CVE-2019-7310

A heap-based buffer over-read (due to an integer signedness error in
the XRef::getEntry function in XRef.cc) allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via a crafted PDF document.

CVE-2019-9200

A heap-based buffer underwrite exists in ImageStream::getLine()
located at Stream.cc that can (for example) be triggered by sending
a crafted PDF file to the pdfimages binary. It allows an attacker to
cause denial-of-service (segmentation fault) or possibly have
unspecified other impact.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib-doc", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler-qt5-dev", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpoppler46", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.26.5-2+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}