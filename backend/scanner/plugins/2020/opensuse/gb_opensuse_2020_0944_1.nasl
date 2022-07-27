# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853255");
  script_version("2020-07-09T12:15:58+0000");
  script_cve_id("CVE-2019-7314", "CVE-2019-9215");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-10 11:44:30 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-08 03:01:16 +0000 (Wed, 08 Jul 2020)");
  script_name("openSUSE: Security Advisory for live555 (openSUSE-SU-2020:0944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:0944-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'live555'
  package(s) announced via the openSUSE-SU-2020:0944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for live555 fixes the following issues:

  - CVE-2019-9215: Malformed headers could have lead to invalid memory
  access in the parseAuthorizationHeader function. (boo#1127341)

  - CVE-2019-7314: Mishandled termination of an RTSP stream after
  RTP/RTCP-over-RTSP has been set up could have lead to a Use-After-Free
  error causing the RTSP server to crash or possibly have unspecified
  other impact. (boo#1124159)

  - Update to version 2019.06.28,

  - Convert to dynamic libraries (boo#1121995):
  + Use make ilinux-with-shared-libraries: build the dynamic libs instead
  of the static one.
  + Use make install instead of a manual file copy script: this also
  reveals that we missed quite a bit of code to be installed before.
  + Split out shared library packages according the SLPP.

  - Use FAT LTO objects in order to provide proper static library.


  This update was imported from the openSUSE:Leap:15.1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-944=1");

  script_tag(name:"affected", value:"'live555' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libBasicUsageEnvironment1", rpm:"libBasicUsageEnvironment1~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libBasicUsageEnvironment1-debuginfo", rpm:"libBasicUsageEnvironment1-debuginfo~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libUsageEnvironment3", rpm:"libUsageEnvironment3~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libUsageEnvironment3-debuginfo", rpm:"libUsageEnvironment3-debuginfo~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgroupsock8", rpm:"libgroupsock8~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgroupsock8-debuginfo", rpm:"libgroupsock8-debuginfo~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libliveMedia66", rpm:"libliveMedia66~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libliveMedia66-debuginfo", rpm:"libliveMedia66-debuginfo~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"live555", rpm:"live555~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"live555-debuginfo", rpm:"live555-debuginfo~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"live555-debugsource", rpm:"live555-debugsource~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"live555-devel", rpm:"live555-devel~2019.06.28~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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