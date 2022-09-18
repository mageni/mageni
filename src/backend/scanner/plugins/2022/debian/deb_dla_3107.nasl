# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893107");
  script_version("2022-09-15T10:11:07+0000");
  script_cve_id("CVE-2020-35525", "CVE-2020-35527", "CVE-2021-20223");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:07 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 01:00:12 +0000 (Wed, 14 Sep 2022)");
  script_name("Debian LTS: Security Advisory for sqlite3 (DLA-3107-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3107-1");
  script_xref(name:"Advisory-ID", value:"DLA-3107-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3'
  package(s) announced via the DLA-3107-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were three issues in SQLite:

* CVE-2020-35525: Prevent a potential null pointer deference issue in
INTERSEC query processing.

* CVE-2020-35527: Prevent an out-of-bounds access issue that could be
exploited via ALTER TABLE in views that have a nested FROM clauses.

* CVE-2021-20223: Prevent an issue with the 'unicode61' tokenizer
related to Unicode control characters ('class Cc') and embedded NUL
characters being misinterpreted as tokens.");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
3.27.2-3+deb10u2.

We recommend that you upgrade your sqlite3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"lemon", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-dev", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-tcl", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sqlite3-doc", ver:"3.27.2-3+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
