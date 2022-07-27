###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1443.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1443-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891443");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2016-10727");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1443-1] evolution-data-server security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-25 00:00:00 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00035.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"evolution-data-server on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in evolution-data-server
version 3.12.9~git20141128.5242b0-2+deb8u4.

We recommend that you upgrade your evolution-data-server packages.");
  script_tag(name:"summary", value:"It was discovered that there was a protocol implementation error in
evolution-data-server where 'STARTTLS not supported' errors from IMAP
servers were ignored leading to the use of insecure connections without
the user's knowledge or consent.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"evolution-data-server", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"evolution-data-server-doc", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gir1.2-ebook-1.2", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gir1.2-ebookcontacts-1.2", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gir1.2-edataserver-1.2", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcamel-1.2-49", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebackend-1.2-7", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebackend1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebook-1.2-14", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebook-contacts-1.2-0", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebook-contacts1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecal-1.2-16", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedata-book-1.2-20", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedata-cal-1.2-23", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedataserver-1.2-18", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"3.12.9~git20141128.5242b0-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}