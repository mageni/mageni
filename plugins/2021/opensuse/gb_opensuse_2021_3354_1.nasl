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
  script_oid("1.3.6.1.4.1.25623.1.0.854212");
  script_version("2021-10-28T05:10:56+0000");
  script_cve_id("CVE-2021-3481");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-28 05:10:56 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 01:02:01 +0000 (Wed, 13 Oct 2021)");
  script_name("openSUSE: Security Advisory for libqt5-qtsvg (openSUSE-SU-2021:3354-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3354-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BBFMOSZDI3WFGNU3EM54DUBD3HAM2LEV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtsvg'
  package(s) announced via the openSUSE-SU-2021:3354-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtsvg fixes the following issues:

  - CVE-2021-3481: Fixed an out of bounds read in function QRadialFetchSimd
       from crafted svg file. (bsc#1184783)");

  script_tag(name:"affected", value:"'libqt5-qtsvg' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5", rpm:"libQt5Svg5~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-debuginfo", rpm:"libQt5Svg5-debuginfo~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-debugsource", rpm:"libqt5-qtsvg-debugsource~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel", rpm:"libqt5-qtsvg-devel~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples", rpm:"libqt5-qtsvg-examples~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples-debuginfo", rpm:"libqt5-qtsvg-examples-debuginfo~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit", rpm:"libQt5Svg5-32bit~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit-debuginfo", rpm:"libQt5Svg5-32bit-debuginfo~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-32bit", rpm:"libqt5-qtsvg-devel-32bit~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-private-headers-devel", rpm:"libqt5-qtsvg-private-headers-devel~5.12.7~3.3.1", rls:"openSUSELeap15.3"))) {
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