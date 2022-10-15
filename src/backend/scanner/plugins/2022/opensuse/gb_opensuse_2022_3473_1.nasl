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
  script_oid("1.3.6.1.4.1.25623.1.0.822589");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2020-10735", "CVE-2021-28861");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-01 01:01:51 +0000 (Sat, 01 Oct 2022)");
  script_name("openSUSE: Security Advisory for python310 (SUSE-SU-2022:3473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3473-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LSVFIZF6ZYMLK2HRCPTYDPZM3P6NDQKU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310'
  package(s) announced via the SUSE-SU-2022:3473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:
  Updated to version 3.10.7:

  - CVE-2020-10735: Fixed DoS due to missing limit of amount of digits when
       converting text to int (bsc#1203125).

  - CVE-2021-28861: Fixed an open redirect in the http server when an URI
       path starts with // (bsc#1202624).");

  script_tag(name:"affected", value:"'python310' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-debuginfo", rpm:"libpython3_10-1_0-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-debuginfo", rpm:"python310-base-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-core-debugsource", rpm:"python310-core-debugsource~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses-debuginfo", rpm:"python310-curses-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm-debuginfo", rpm:"python310-dbm-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debuginfo", rpm:"python310-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debugsource", rpm:"python310-debugsource~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc", rpm:"python310-doc~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc-devhelp", rpm:"python310-doc-devhelp~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite", rpm:"python310-testsuite~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite-debuginfo", rpm:"python310-testsuite-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk-debuginfo", rpm:"python310-tk-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit", rpm:"libpython3_10-1_0-32bit~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit-debuginfo", rpm:"libpython3_10-1_0-32bit-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit", rpm:"python310-32bit~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit-debuginfo", rpm:"python310-32bit-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit", rpm:"python310-base-32bit~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit-debuginfo", rpm:"python310-base-32bit-debuginfo~3.10.7~150400.4.10.1", rls:"openSUSELeap15.4"))) {
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