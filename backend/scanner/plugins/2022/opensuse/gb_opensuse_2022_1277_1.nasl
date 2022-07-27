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
  script_oid("1.3.6.1.4.1.25623.1.0.854607");
  script_version("2022-04-29T06:36:55+0000");
  script_cve_id("CVE-2017-13735", "CVE-2017-14608", "CVE-2018-19565", "CVE-2018-19566", "CVE-2018-19567", "CVE-2018-19568", "CVE-2018-19655", "CVE-2018-5801", "CVE-2018-5805", "CVE-2018-5806", "CVE-2021-3624");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-29 10:20:12 +0000 (Fri, 29 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-21 01:01:19 +0000 (Thu, 21 Apr 2022)");
  script_name("openSUSE: Security Advisory for dcraw (SUSE-SU-2022:1277-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1277-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YDVWQ5ZUMZUOMBBPVXPXX6XNCBNZ2BMJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcraw'
  package(s) announced via the SUSE-SU-2022:1277-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dcraw fixes the following issues:

  - CVE-2017-13735: Fixed a denial of service issue due to a floating point
       exception (bsc#1056170).

  - CVE-2017-14608: Fixed an invalid memory access that could lead to
       information disclosure or denial of service (bsc#1063798).

  - CVE-2018-19655: Fixed a buffer overflow that could lead to an
       application crash (bsc#1117896).

  - CVE-2018-5801: Fixed an invalid memory access that could lead to denial
       of service (bsc#1084690).

  - CVE-2018-5805: Fixed a buffer overflow that could lead to an application
       crash (bsc#1097973).

  - CVE-2018-5806: Fixed an invalid memory access that could lead to denial
       of service (bsc#1097974).

  - CVE-2018-19565: Fixed an invalid memory access that could lead to
       information disclosure or denial of service (bsc#1117622).

  - CVE-2018-19566: Fixed an invalid memory access that could lead to
       information disclosure or denial of service (bsc#1117517).

  - CVE-2018-19567: Fixed a denial of service issue due to a floating point
       exception (bsc#1117512).

  - CVE-2018-19568: Fixed a denial of service issue due to a floating point
       exception (bsc#1117436).

  - CVE-2021-3624: Fixed a buffer overflow that could lead to code execution
       or denial of service (bsc#1189642).
  Non-security fixes:

  - Updated to version 9.28.0.");

  script_tag(name:"affected", value:"'dcraw' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcraw", rpm:"dcraw~9.28.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-debuginfo", rpm:"dcraw-debuginfo~9.28.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-debugsource", rpm:"dcraw-debugsource~9.28.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-lang", rpm:"dcraw-lang~9.28.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dcraw", rpm:"dcraw~9.28.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-debuginfo", rpm:"dcraw-debuginfo~9.28.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-debugsource", rpm:"dcraw-debugsource~9.28.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcraw-lang", rpm:"dcraw-lang~9.28.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
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