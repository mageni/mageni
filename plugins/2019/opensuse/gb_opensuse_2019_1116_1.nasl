# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852375");
  script_version("2019-04-03T06:41:59+0000");
  script_cve_id("CVE-2018-19869");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-03 06:41:59 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-03 06:41:59 +0000 (Wed, 03 Apr 2019)");
  script_name("openSUSE Update for libqt5-qtsvg openSUSE-SU-2019:1116-1 (libqt5-qtsvg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtsvg'
  package(s) announced via the openSUSE-SU-2019:1116_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtsvg fixes the following issues:

  Security issues fixed:

  - CVE-2018-19869: Fixed Denial of Service when parsing malformed URL
  reference (bsc#1118599)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1116=1");

  script_tag(name:"affected", value:"'libqt5-qtsvg' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5", rpm:"libQt5Svg5~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-debuginfo", rpm:"libQt5Svg5-debuginfo~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-debugsource", rpm:"libqt5-qtsvg-debugsource~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel", rpm:"libqt5-qtsvg-devel~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples", rpm:"libqt5-qtsvg-examples~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples-debuginfo", rpm:"libqt5-qtsvg-examples-debuginfo~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit", rpm:"libQt5Svg5-32bit~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit-debuginfo", rpm:"libQt5Svg5-32bit-debuginfo~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-32bit", rpm:"libqt5-qtsvg-devel-32bit~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-private-headers-devel", rpm:"libqt5-qtsvg-private-headers-devel~5.9.4~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
