# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852938");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-14491", "CVE-2019-14492", "CVE-2019-15939");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:46:42 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for opencv openSUSE-SU-2019:2671-1 (opencv)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00025.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencv'
  package(s) announced via the openSUSE-SU-2019:2671_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opencv fixes the following issues:

  Security issues fixed:

  - CVE-2019-14491: Fixed an out of bounds read in the function
  cv:predictOrdered<cv:HaarEvaluator>, leading to DOS (bsc#1144352).

  - CVE-2019-14492: Fixed an out of bounds read/write in the function
  HaarEvaluator:OptFeature:calc, which leads to denial of service
  (bsc#1144348).

  - CVE-2019-15939: Fixed a divide-by-zero error in
  cv:HOGDescriptor:getDescriptorSize (bsc#1149742).

  Non-security issue fixed:

  - Fixed an issue in opencv-devel that broke builds with 'No rule to make
  target opencv_calib3d-NOTFOUND' (bsc#1154091).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2671=1");

  script_tag(name:"affected", value:"'opencv' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libopencv3_3", rpm:"libopencv3_3~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv3_3-debuginfo", rpm:"libopencv3_3-debuginfo~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv", rpm:"opencv~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-debuginfo", rpm:"opencv-debuginfo~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-debugsource", rpm:"opencv-debugsource~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-devel", rpm:"opencv-devel~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-doc", rpm:"opencv-doc~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-opencv", rpm:"python2-opencv~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-opencv-debuginfo", rpm:"python2-opencv-debuginfo~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-opencv", rpm:"python3-opencv~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-opencv-debuginfo", rpm:"python3-opencv-debuginfo~3.3.1~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
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
