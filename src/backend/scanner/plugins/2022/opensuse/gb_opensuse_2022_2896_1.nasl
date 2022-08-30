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
  script_oid("1.3.6.1.4.1.25623.1.0.854924");
  script_version("2022-08-26T08:41:19+0000");
  script_cve_id("CVE-2020-25713");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-26 08:41:19 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-20 20:15:00 +0000 (Thu, 20 May 2021)");
  script_tag(name:"creation_date", value:"2022-08-26 01:02:27 +0000 (Fri, 26 Aug 2022)");
  script_name("openSUSE: Security Advisory for raptor (SUSE-SU-2022:2896-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2896-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JKGFUADCY4BJCQUXYVD7FL6UHZ5ISTHC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor'
  package(s) announced via the SUSE-SU-2022:2896-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for raptor fixes the following issues:

  - CVE-2020-25713: Fixed an out of bounds access triggered via a malformed
       input file (bsc#1178903).");

  script_tag(name:"affected", value:"'raptor' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libraptor-devel", rpm:"libraptor-devel~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0", rpm:"libraptor2-0~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-debuginfo", rpm:"libraptor2-0-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor", rpm:"raptor~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor-debuginfo", rpm:"raptor-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor-debugsource", rpm:"raptor-debugsource~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-32bit", rpm:"libraptor2-0-32bit~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-32bit-debuginfo", rpm:"libraptor2-0-32bit-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libraptor-devel", rpm:"libraptor-devel~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0", rpm:"libraptor2-0~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-debuginfo", rpm:"libraptor2-0-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor", rpm:"raptor~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor-debuginfo", rpm:"raptor-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor-debugsource", rpm:"raptor-debugsource~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-32bit", rpm:"libraptor2-0-32bit~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-32bit-debuginfo", rpm:"libraptor2-0-32bit-debuginfo~2.0.15~150200.9.12.1", rls:"openSUSELeap15.3"))) {
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