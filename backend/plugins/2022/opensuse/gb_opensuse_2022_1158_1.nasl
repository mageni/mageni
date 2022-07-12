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
  script_oid("1.3.6.1.4.1.25623.1.0.854615");
  script_version("2022-05-23T12:36:28+0000");
  script_cve_id("CVE-2022-1271");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-23 12:36:28 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-17 12:05:38 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for xz (SUSE-SU-2022:1158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1158-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZDJ2YRE7EVXHNUZVGSDDUVQ3NP3OUNTB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xz'
  package(s) announced via the SUSE-SU-2022:1158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xz fixes the following issues:

  - CVE-2022-1271: Fixed an incorrect escaping of malicious filenames
       (ZDI-CAN-16587). (bsc#1198062)");

  script_tag(name:"affected", value:"'xz' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"liblzma5", rpm:"liblzma5~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-debuginfo", rpm:"liblzma5-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz", rpm:"xz~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-debuginfo", rpm:"xz-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-debugsource", rpm:"xz-debugsource~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-devel", rpm:"xz-devel~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-static-devel", rpm:"xz-static-devel~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-lang", rpm:"xz-lang~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-32bit", rpm:"liblzma5-32bit~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-32bit-debuginfo", rpm:"liblzma5-32bit-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-devel-32bit", rpm:"xz-devel-32bit~5.2.3~150000.4.7.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"liblzma5", rpm:"liblzma5~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-debuginfo", rpm:"liblzma5-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz", rpm:"xz~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-debuginfo", rpm:"xz-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-debugsource", rpm:"xz-debugsource~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-devel", rpm:"xz-devel~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-static-devel", rpm:"xz-static-devel~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-lang", rpm:"xz-lang~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-32bit", rpm:"liblzma5-32bit~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5-32bit-debuginfo", rpm:"liblzma5-32bit-debuginfo~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz-devel-32bit", rpm:"xz-devel-32bit~5.2.3~150000.4.7.1", rls:"openSUSELeap15.3"))) {
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