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
  script_oid("1.3.6.1.4.1.25623.1.0.854994");
  script_version("2022-09-21T10:12:28+0000");
  script_cve_id("CVE-2021-36690", "CVE-2022-35737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 02:15:00 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2022-09-20 01:01:53 +0000 (Tue, 20 Sep 2022)");
  script_name("openSUSE: Security Advisory for sqlite3 (SUSE-SU-2022:3307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3307-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/THOVLOXN6BGIHXJJKPRHHF3ZWEYX2TPL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3'
  package(s) announced via the SUSE-SU-2022:3307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sqlite3 fixes the following issues:

  - CVE-2022-35737: Fixed an array-bounds overflow if billions of bytes are
       used in a string argument to a C API (bnc#1201783).

  - CVE-2021-36690: Fixed an issue with the SQLite Expert extension when a
       column has no collating sequence (bsc#1189802).

  - Package the Tcl bindings here again so that we only ship one copy of
       SQLite (bsc#1195773).");

  script_tag(name:"affected", value:"'sqlite3' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0", rpm:"libsqlite3-0~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-debuginfo", rpm:"libsqlite3-0-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debuginfo", rpm:"sqlite3-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debugsource", rpm:"sqlite3-debugsource~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-devel", rpm:"sqlite3-devel~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-doc", rpm:"sqlite3-doc~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit", rpm:"libsqlite3-0-32bit~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit-debuginfo", rpm:"libsqlite3-0-32bit-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0", rpm:"libsqlite3-0~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-debuginfo", rpm:"libsqlite3-0-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debuginfo", rpm:"sqlite3-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debugsource", rpm:"sqlite3-debugsource~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-devel", rpm:"sqlite3-devel~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit", rpm:"libsqlite3-0-32bit~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit-debuginfo", rpm:"libsqlite3-0-32bit-debuginfo~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-doc", rpm:"sqlite3-doc~3.39.3~150000.3.17.1", rls:"openSUSELeap15.3"))) {
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