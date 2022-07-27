###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1633.nasl 14282 2019-03-18 14:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1633-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.891633");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2017-10989", "CVE-2017-2518", "CVE-2017-2519", "CVE-2017-2520", "CVE-2018-8740");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1633-1] sqlite3 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-14 00:00:00 +0100 (Mon, 14 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00009.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"sqlite3 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.8.7.1-1+deb8u4.

We recommend that you upgrade your sqlite3 packages.");
  script_tag(name:"summary", value:"Several flaws were corrected in SQLite, an SQL database engine.

CVE-2017-2518

A use-after-free bug in the query optimizer may cause a
buffer overflow and application crash via a crafted SQL statement.

CVE-2017-2519

Insufficient size of the reference count on Table objects
could lead to a denial-of-service or arbitrary code execution.

CVE-2017-2520

The sqlite3_value_text() interface returned a buffer that was not
large enough to hold the complete string plus zero terminator when
the input was a zeroblob. This could lead to arbitrary code
execution or a denial-of-service.

CVE-2017-10989

SQLite mishandles undersized RTree blobs in a crafted database
leading to a heap-based buffer over-read or possibly unspecified
other impact.

CVE-2018-8740

Databases whose schema is corrupted using a CREATE TABLE AS
statement could cause a NULL pointer dereference.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"lemon", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsqlite3-0-dbg", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsqlite3-dev", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsqlite3-tcl", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sqlite3", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sqlite3-doc", ver:"3.8.7.1-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}