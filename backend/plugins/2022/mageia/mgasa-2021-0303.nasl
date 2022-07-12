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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0303");
  script_cve_id("CVE-2020-11655", "CVE-2020-13434", "CVE-2020-13435", "CVE-2020-13630", "CVE-2020-13631", "CVE-2020-13632", "CVE-2020-13871", "CVE-2020-15358", "CVE-2020-9327");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0303");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0303.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26270");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:4442");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2340");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/BN32AGQPMHZRNM6P6L5GZPETOWTGXOKP/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4438-1");
  script_xref(name:"URL", value:"https://www.sqlite.org/releaselog/3_32_3.html");
  script_xref(name:"URL", value:"https://www.sqlite.org/releaselog/3_32_2.html");
  script_xref(name:"URL", value:"https://www.sqlite.org/releaselog/3_32_1.html");
  script_xref(name:"URL", value:"https://www.sqlite.org/releaselog/3_32_0.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4394-1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2221");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3' package(s) announced via the MGASA-2021-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL
pointer dereference and segmentation fault because of generated column
optimizations (CVE-2020-9327).

SQLite through 3.31.1 allows attackers to cause a denial of service
(segmentation fault) via a malformed window-function query because the
AggInfo object's initialization is mishandled
(CVE-2020-11655).

SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in
printf.c (CVE-2020-13434).

SQLite through 3.32.0 has a segmentation fault in sqlite3ExprCodeTarget in
expr.c (CVE-2020-13435).

ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow,
related to the snippet feature (CVE-2020-13630).

SQLite before 3.32.0 allows a virtual table to be renamed to the name of one
of its shadow tables, related to alter.c and build.c (CVE-2020-13631).

ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference
via a crafted matchinfo() query (CVE-2020-13632).

SQLite 3.32.2 has a use-after-free in resetAccumulator in select.c because the
parse tree rewrite for window functions is too late (CVE-2020-13871).

In SQLite before 3.32.3, select.c mishandles query-flattener optimization,
leading to a multiSelectOrderBy heap overflow because of misuse of transitive
properties for constant propagation (CVE-2020-15358).");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lemon", rpm:"lemon~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-devel", rpm:"lib64sqlite3-devel~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-static-devel", rpm:"lib64sqlite3-static-devel~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3_0", rpm:"lib64sqlite3_0~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-devel", rpm:"libsqlite3-devel~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-static-devel", rpm:"libsqlite3-static-devel~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3_0", rpm:"libsqlite3_0~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tcl", rpm:"sqlite3-tcl~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tools", rpm:"sqlite3-tools~3.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
