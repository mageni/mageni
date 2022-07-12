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
  script_oid("1.3.6.1.4.1.25623.1.0.852554");
  script_version("2019-06-13T11:51:34+0000");
  script_cve_id("CVE-2018-0734", "CVE-2018-11763", "CVE-2018-11784", "CVE-2018-3309", "CVE-2019-2446", "CVE-2019-2448", "CVE-2019-2450", "CVE-2019-2451", "CVE-2019-2500", "CVE-2019-2501", "CVE-2019-2504", "CVE-2019-2505", "CVE-2019-2506", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2511", "CVE-2019-2520", "CVE-2019-2521", "CVE-2019-2522", "CVE-2019-2523", "CVE-2019-2524", "CVE-2019-2525", "CVE-2019-2526", "CVE-2019-2527", "CVE-2019-2548", "CVE-2019-2552", "CVE-2019-2553", "CVE-2019-2554", "CVE-2019-2555", "CVE-2019-2556");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-06-13 11:51:34 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-12 02:00:41 +0000 (Wed, 12 Jun 2019)");
  script_name("openSUSE Update for virtualbox openSUSE-SU-2019:1547-1 (virtualbox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00030.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2019:1547_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox to version 5.2.24 fixes the following issues:

  Multiple security issues fixed:

  CVE-2019-2500, CVE-2019-2524, CVE-2019-2552, CVE-2018-3309,
  CVE-2019-2520 CVE-2019-2521, CVE-2019-2522, CVE-2019-2523, CVE-2019-2526,
  CVE-2019-2548 CVE-2018-11763, CVE-2019-2511, CVE-2019-2508, CVE-2019-2509,
  CVE-2019-2527 CVE-2019-2450, CVE-2019-2451, CVE-2019-2555, CVE-2019-2554,
  CVE-2019-2556 CVE-2018-11784, CVE-2018-0734, CVE-2019-2525, CVE-2019-2446,
  CVE-2019-2448 CVE-2019-2501, CVE-2019-2504, CVE-2019-2505, CVE-2019-2506,
  and CVE-2019-2553 (bsc#1122212).

  Other issues fixed:

  - Linux Additions: fix for building vboxvideo on EL 7.6 standard kernel,
  contributed by Robert Conde

  - USB: fixed a problem causing failures attaching SuperSpeed devices which
  report USB version 3.1 (rather than 3.0) on Windows hosts

  - Audio: added support for surround speaker setups used by Windows 10
  Build 1809

  - Linux hosts: fixed conflict between Debian and Oracle build desktop files

  - Linux guests: fixed building drivers on SLES 12.4

  - Linux guests: fixed building shared folder driver with older kernels


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1547=1");

  script_tag(name:"affected", value:"'virtualbox' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.2.24_k4.12.14_lp150.12.61~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>virtualbox-guest-kmp-default-debuginfo", rpm:"<br>virtualbox-guest-kmp-default-debuginfo~5.2.24_k4.12.14_lp150.12.61~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.2.24_k4.12.14_lp150.12.61~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>virtualbox-host-kmp-default-debuginfo", rpm:"<br>virtualbox-host-kmp-default-debuginfo~5.2.24_k4.12.14_lp150.12.61~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.2.24~lp150.4.33.1", rls:"openSUSELeap15.0"))) {
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