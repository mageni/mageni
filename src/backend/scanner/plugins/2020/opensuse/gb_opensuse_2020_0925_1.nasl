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
  script_oid("1.3.6.1.4.1.25623.1.0.853250");
  script_version("2020-07-09T12:15:58+0000");
  script_cve_id("CVE-2020-2741", "CVE-2020-2742", "CVE-2020-2743", "CVE-2020-2748", "CVE-2020-2758", "CVE-2020-2894", "CVE-2020-2902", "CVE-2020-2905", "CVE-2020-2907", "CVE-2020-2908", "CVE-2020-2909", "CVE-2020-2910", "CVE-2020-2911", "CVE-2020-2913", "CVE-2020-2914", "CVE-2020-2929", "CVE-2020-2951", "CVE-2020-2958", "CVE-2020-2959");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-10 11:44:30 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-04 03:13:40 +0000 (Sat, 04 Jul 2020)");
  script_name("openSUSE: Security Advisory for Virtualbox (openSUSE-SU-2020:0925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0925-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Virtualbox'
  package(s) announced via the openSUSE-SU-2020:0925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Virtualbox was updated to 6.0.22 (released May 15 2020 by Oracle)

  This is a maintenance release. The following items were fixed and/or added:

  Guest Additions: Build problems fix with Oracle Linux 8.2 (Red Hat
  compatible kernel) / Red Hat Enterprise Linux 8.2 / CentOS 8.2 (bug
  #19391) Guest Control/VBoxManage: fix handling of multiple environment
  variables supplied to 'VBoxManage guestcontrol VM run' (6.1.6/6.0.20
  regression, bug #19518)

  Version bump to 6.0.20 (released April 14 2020 by Oracle)

  This is a maintenance release. The following items were fixed and/or added:

  - USB: Multiple enhancements improving prformance and stability

  - VBoxManage: Multiple fixes for guestcontrol command

  - Graphics: Enhancements in 2D and 3D acceleration and rendering

  - API: Fix for exception handling bug in Python bindings

  - Linux host and guest: Support Linux kernel 5.6 (bug #19312)

  This update fixes the following security issues: CVE-2020-2741,
  CVE-2020-2742, CVE-2020-2743, CVE-2020-2748, CVE-2020-2758, CVE-2020-2894,
  CVE-2020-2902, CVE-2020-2905, CVE-2020-2907, CVE-2020-2908, CVE-2020-2909,
  CVE-2020-2910, CVE-2020-2911, CVE-2020-2913, CVE-2020-2914, CVE-2020-2929,
  CVE-2020-2951, CVE-2020-2958, CVE-2020-2959 (bsc#1169628)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-925=1");

  script_tag(name:"affected", value:"'Virtualbox' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.0.22_k4.12.14_lp151.28.52~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.0.22_k4.12.14_lp151.28.52~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.0.22~lp151.2.15.1", rls:"openSUSELeap15.1"))) {
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