# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.892340");
  script_version("2020-08-23T03:00:23+0000");
  script_cve_id("CVE-2018-20346", "CVE-2018-20506", "CVE-2018-8740", "CVE-2019-16168", "CVE-2019-20218", "CVE-2019-5827", "CVE-2019-9936", "CVE-2019-9937", "CVE-2020-11655", "CVE-2020-13434", "CVE-2020-13630", "CVE-2020-13632", "CVE-2020-13871");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-25 10:44:06 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-23 03:00:23 +0000 (Sun, 23 Aug 2020)");
  script_name("Debian LTS: Security Advisory for sqlite3 (DLA-2340-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2340-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3'
  package(s) announced via the DLA-2340-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in sqlite3, a C library that
implements an SQL database engine.

CVE-2018-8740

Databases whose schema is corrupted using a CREATE TABLE AS statement
could cause a NULL pointer dereference.

CVE-2018-20346

When the FTS3 extension is enabled, sqlite3 encounters an integer
overflow (and resultant buffer overflow) for FTS3 queries that occur
after crafted changes to FTS3 shadow tables, allowing remote
attackers to execute arbitrary code by leveraging the ability to run
arbitrary SQL statements.

CVE-2018-20506

When the FTS3 extension is enabled, sqlite3 encounters an integer
overflow (and resultant buffer overflow) for FTS3 queries in a
'merge' operation that occurs after crafted changes to FTS3 shadow
tables, allowing remote attackers to execute arbitrary code by
leveraging the ability to run arbitrary SQL statements

CVE-2019-5827

Integer overflow allowed a remote attacker to potentially exploit
heap corruption via a crafted HTML page, primarily impacting
chromium.

CVE-2019-9936

Running fts5 prefix queries inside a transaction could trigger a
heap-based buffer over-read, which may lead to an information leak.

CVE-2019-9937

Interleaving reads and writes in a single transaction with an fts5
virtual table will lead to a NULL Pointer Dereference.

CVE-2019-16168

A browser or other application can be triggered to crash because of
inadequate parameter validation which could lead to a divide-by-zero
error.

CVE-2019-20218

WITH stack unwinding proceeds even after a parsing error, resulting
in a possible application crash.

CVE-2020-13630

The code related to the snippet feature exhibits a use-after-free
defect.

CVE-2020-13632

A crafted matchinfo() query can lead to a NULL pointer dereference.

CVE-2020-13871

The parse tree rewrite for window functions is too late, leading to
a use-after-free defect.

CVE-2020-11655

An improper initialization of AggInfo objects allows attackers to
cause a denial of service (segmentation fault) via a malformed
window-function query.

CVE-2020-13434

The code in sqlite3_str_vappendf in printf.c contains an integer
overflow defect.");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.16.2-5+deb9u2.

We recommend that you upgrade your sqlite3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"lemon", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0-dbg", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-dev", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-tcl", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sqlite3-doc", ver:"3.16.2-5+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
