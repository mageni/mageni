# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853983");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2019-19244", "CVE-2019-19317", "CVE-2019-19603", "CVE-2019-19645", "CVE-2019-19646", "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19924", "CVE-2019-19925", "CVE-2019-19926", "CVE-2019-19959", "CVE-2019-20218", "CVE-2020-13434", "CVE-2020-13435", "CVE-2020-13630", "CVE-2020-13631", "CVE-2020-13632", "CVE-2020-15358", "CVE-2020-9327");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-15 03:02:43 +0000 (Thu, 15 Jul 2021)");
  script_name("openSUSE: Security Advisory for sqlite3 (openSUSE-SU-2021:2320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2320-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JD4EZ74IZ57MKTDKDVIUAIG6VCAEKMD5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3'
  package(s) announced via the openSUSE-SU-2021:2320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sqlite3 fixes the following issues:

  - Update to version 3.36.0

  - CVE-2020-15358: heap-based buffer overflow in multiSelectOrderBy due to
       mishandling of query-flattener
       optimization (bsc#1173641)

  - CVE-2020-9327: NULL pointer dereference and segmentation fault because
       of generated column optimizations in isAuxiliaryVtabOperator
       (bsc#1164719)

  - CVE-2019-20218: selectExpander in select.c proceeds with WITH stack
       unwinding even after a parsing error (bsc#1160439)

  - CVE-2019-19959: memory-management error via ext/misc/zipfile.c involving
       embedded &#x27 \0&#x27  input (bsc#1160438)

  - CVE-2019-19923: improper handling  of  certain uses of SELECT DISTINCT
       in flattenSubquery may lead to null pointer dereference (bsc#1160309)

  - CVE-2019-19924: improper error handling in sqlite3WindowRewrite()
       (bsc#1159850)

  - CVE-2019-19925: improper handling of NULL pathname during an update of a
       ZIP archive (bsc#1159847)

  - CVE-2019-19926: improper handling  of certain errors during parsing
       multiSelect in select.c (bsc#1159715)

  - CVE-2019-19880: exprListAppendList in window.c allows attackers to
       trigger an invalid pointer dereference (bsc#1159491)

  - CVE-2019-19603: during handling of CREATE TABLE and CREATE VIEW
       statements, does not consider confusion with a shadow table name
       (bsc#1158960)

  - CVE-2019-19646: pragma.c mishandles NOT NULL in an integrity_check
       PRAGMA command in certain cases of generated columns (bsc#1158959)

  - CVE-2019-19645: alter.c allows attackers to trigger infinite recursion
       via certain types of self-referential views in conjunction with ALTER
       TABLE statements (bsc#1158958)

  - CVE-2019-19317: lookupName in resolve.c omits bits from the colUsed
       bitmask in the case of a generated column, which allows attackers to
       cause a denial of service (bsc#1158812)

  - CVE-2019-19244: sqlite3, sqlite2, sqlite: The function sqlite3Select in
       select.c allows a crash if a sub-select uses both DISTINCT and window
       functions, and also has certain ORDER BY usage (bsc#1157818)

  - CVE-2015-3415: sqlite3VdbeExec comparison operator vulnerability
       (bsc#928701)

  - CVE-2015-3414: sqlite3, sqlite2: dequoting of collation-sequence names
       (bsc#928700)

  - CVE-2020-13434: integer overflow in sqlite3_str_vappendf (bsc#1172115)

  - CVE-2020-13630: (bsc#1172234: use-after-free in fts3EvalNextRow

  - CVE-2020-13631: virtual table allowed to be renamed to one of its shadow
     ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'sqlite3' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0", rpm:"libsqlite3-0~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-debuginfo", rpm:"libsqlite3-0-debuginfo~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debuginfo", rpm:"sqlite3-debuginfo~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debugsource", rpm:"sqlite3-debugsource~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-devel", rpm:"sqlite3-devel~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-doc", rpm:"sqlite3-doc~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit", rpm:"libsqlite3-0-32bit~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit-debuginfo", rpm:"libsqlite3-0-32bit-debuginfo~3.36.0~3.12.1", rls:"openSUSELeap15.3"))) {
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