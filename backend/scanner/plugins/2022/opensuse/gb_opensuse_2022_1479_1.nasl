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
  script_oid("1.3.6.1.4.1.25623.1.0.854622");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2021-26926", "CVE-2021-26927", "CVE-2021-3443", "CVE-2021-3467");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-22 16:09:00 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:05:51 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for jasper (SUSE-SU-2022:1479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1479-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T3J3HHAVYMMOAGIZ7DYMCAOKYZPJOLUN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper'
  package(s) announced via the SUSE-SU-2022:1479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following issues:

  - CVE-2021-3467: Fixed NULL pointer deref in jp2_decode() (bsc#1184757).

  - CVE-2021-3443: Fixed NULL pointer deref in jp2_decode() (bsc#1184798).

  - CVE-2021-26927: Fixed NULL pointer deref in jp2_decode() (bsc#1182104).

  - CVE-2021-26926: Fixed an out of bounds read in jp2_decode()
       (bsc#1182105).");

  script_tag(name:"affected", value:"'jasper' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"jasper", rpm:"jasper~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debuginfo", rpm:"jasper-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debugsource", rpm:"jasper-debugsource~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4", rpm:"libjasper4~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-debuginfo", rpm:"libjasper4-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit", rpm:"libjasper4-32bit~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit-debuginfo", rpm:"libjasper4-32bit-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"jasper", rpm:"jasper~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debuginfo", rpm:"jasper-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debugsource", rpm:"jasper-debugsource~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4", rpm:"libjasper4~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-debuginfo", rpm:"libjasper4-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit", rpm:"libjasper4-32bit~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit-debuginfo", rpm:"libjasper4-32bit-debuginfo~2.0.14~150000.3.25.1", rls:"openSUSELeap15.3"))) {
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