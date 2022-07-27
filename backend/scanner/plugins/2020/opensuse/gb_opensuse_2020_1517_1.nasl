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
  script_oid("1.3.6.1.4.1.25623.1.0.853451");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2016-9398", "CVE-2016-9399", "CVE-2017-14132", "CVE-2017-5499", "CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-19139", "CVE-2018-19543", "CVE-2018-20570", "CVE-2018-20622", "CVE-2018-9252");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-25 03:01:09 +0000 (Fri, 25 Sep 2020)");
  script_name("openSUSE: Security Advisory for jasper (openSUSE-SU-2020:1517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1517-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00082.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper'
  package(s) announced via the openSUSE-SU-2020:1517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following issues:

  - CVE-2016-9398: Improved patch for already fixed issue (bsc#1010979).

  - CVE-2016-9399: Fix assert in calcstepsizes (bsc#1010980).

  - CVE-2017-5499: Validate component depth bit (bsc#1020451).

  - CVE-2017-5503: Check bounds in jas_seq2d_bindsub() (bsc#1020456).

  - CVE-2017-5504: Check bounds in jas_seq2d_bindsub() (bsc#1020458).

  - CVE-2017-5505: Check bounds in jas_seq2d_bindsub() (bsc#1020460).

  - CVE-2017-14132: Fix heap base overflow in by checking components
  (bsc#1057152).

  - CVE-2018-9252: Fix reachable assertion in jpc_abstorelstepsize
  (bsc#1088278).

  - CVE-2018-18873: Fix null pointer deref in ras_putdatastd (bsc#1114498).

  - CVE-2018-19139: Fix mem leaks by registering jpc_unk_destroyparms
  (bsc#1115637).

  - CVE-2018-19543, bsc#1045450 CVE-2017-9782: Fix numchans mixup
  (bsc#1117328).

  - CVE-2018-20570: Fix heap based buffer over-read in jp2_encode
  (bsc#1120807).

  - CVE-2018-20622: Fix memory leak in jas_malloc.c (bsc#1120805).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1517=1");

  script_tag(name:"affected", value:"'jasper' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"jasper", rpm:"jasper~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debuginfo", rpm:"jasper-debuginfo~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jasper-debugsource", rpm:"jasper-debugsource~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4", rpm:"libjasper4~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-debuginfo", rpm:"libjasper4-debuginfo~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit", rpm:"libjasper4-32bit~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4-32bit-debuginfo", rpm:"libjasper4-32bit-debuginfo~2.0.14~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
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