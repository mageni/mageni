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
  script_oid("1.3.6.1.4.1.25623.1.0.852724");
  script_version("2019-10-04T07:25:00+0000");
  script_cve_id("CVE-2019-9511", "CVE-2019-9513");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-10-04 07:25:00 +0000 (Fri, 04 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-02 02:00:55 +0000 (Wed, 02 Oct 2019)");
  script_name("openSUSE Update for nghttp2 openSUSE-SU-2019:2234-1 (nghttp2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2'
  package(s) announced via the openSUSE-SU-2019:2234_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nghttp2 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
  resource loops, potentially leading to a denial of service (bsc#1146184).

  - CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
  window size manipulation and stream prioritization manipulation,
  potentially leading to a denial of service (bsc#11461).

  Bug fixes and enhancements:

  - Fixed mistake in spec file (bsc#1125689)

  - Fixed build issue with boost 1.70.0 (bsc#1134616)

  - Feature: Add W&S module (FATE#326776, bsc#1112438)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2234=1");

  script_tag(name:"affected", value:"'nghttp2' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio-devel", rpm:"libnghttp2_asio-devel~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1", rpm:"libnghttp2_asio1~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-debuginfo", rpm:"libnghttp2_asio1-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-python-debugsource", rpm:"nghttp2-python-debugsource~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2", rpm:"python3-nghttp2~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2-debuginfo", rpm:"python3-nghttp2-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit", rpm:"libnghttp2-14-32bit~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit-debuginfo", rpm:"libnghttp2-14-32bit-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit", rpm:"libnghttp2_asio1-32bit~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit-debuginfo", rpm:"libnghttp2_asio1-32bit-debuginfo~1.39.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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