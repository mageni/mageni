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
  script_oid("1.3.6.1.4.1.25623.1.0.852581");
  script_version("2019-06-27T06:30:18+0000");
  script_cve_id("CVE-2018-19800", "CVE-2018-19801", "CVE-2018-19802");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-06-27 06:30:18 +0000 (Thu, 27 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-25 02:00:59 +0000 (Tue, 25 Jun 2019)");
  script_name("openSUSE Update for aubio openSUSE-SU-2019:1618-1 (aubio)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00063.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aubio'
  package(s) announced via the openSUSE-SU-2019:1618_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aubio fixes the following issues:

  Fixed security issues leading to buffer overflows or segfaults
  (CVE-2018-19800, boo#1137828, CVE-2018-19801, boo#1137822, CVE-2018-19802,
  boo#1137823):


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1618=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1618=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1618=1");

  script_tag(name:"affected", value:"'aubio' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"aubio-debugsource", rpm:"aubio-debugsource~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aubio-tools", rpm:"aubio-tools~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aubio-tools-debuginfo", rpm:"aubio-tools-debuginfo~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio-devel", rpm:"libaubio-devel~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio4", rpm:"libaubio4~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio4-debuginfo", rpm:"libaubio4-debuginfo~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio4-32bit", rpm:"libaubio4-32bit~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio4-debuginfo-32bit", rpm:"libaubio4-debuginfo-32bit~0.4.1~9.13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"aubio-debugsource", rpm:"aubio-debugsource~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aubio-tools", rpm:"aubio-tools~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aubio-tools-debuginfo", rpm:"aubio-tools-debuginfo~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio-devel", rpm:"libaubio-devel~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio5", rpm:"libaubio5~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio5-debuginfo", rpm:"libaubio5-debuginfo~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio5-32bit", rpm:"libaubio5-32bit~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio5-32bit-debuginfo", rpm:"libaubio5-32bit-debuginfo~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aubio-debugsource", rpm:"python-aubio-debugsource~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-aubio", rpm:"python2-aubio~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-aubio-debuginfo", rpm:"python2-aubio-debuginfo~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aubio", rpm:"python3-aubio~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aubio-debuginfo", rpm:"python3-aubio-debuginfo~0.4.6~lp150.3.10.1", rls:"openSUSELeap15.0"))) {
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
