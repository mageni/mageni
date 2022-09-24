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
  script_oid("1.3.6.1.4.1.25623.1.0.854990");
  script_version("2022-09-20T10:11:40+0000");
  script_cve_id("CVE-2022-21554", "CVE-2022-21571");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-17 01:02:42 +0000 (Sat, 17 Sep 2022)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2022:10122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10122-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IW7PPIWGXC43ULEMZIOEZJIZ4XLRO2X4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2022:10122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

  - Remove package virtualbox-guest-x11, which is no longer needed.

  - Fix screen resizing under Wayland (boo#1194126 and boo#1194126)
  Version bump to 6.1.36 released by Oracle July 19 2022
  This is a maintenance release. The following items were fixed and/or added:

  - VMM: Fixed possible Linux guest kernel crash when configuring
       Speculative Store Bypass for a single vCPU VM

  - GUI: In the storage page of the virtual machine settings dialog, fixed a
       bug which disrupted mouse interaction with the native file selector on
       KDE

  - NAT: Prevent issue when host resolver incorrectly returned NXDOMAIN for
       unsupported queries (bug #20977)

  - Audio: General improvements in saved state area

  - Recording: Various fixes for settings handling

  - VGA: Performance improvements for screen updates when VBE banking is used

  - USB: Fixed rare crashes when detaching a USB device

  - ATA: Fixed NT4 guests taking a minute to eject CDs

  - vboximg-mount: Fixed broken write support (bug #20896)

  - SDK: Fixed Python bindings incorrectly trying to convert arbitrary byte
       data into unicode objects with Python 3, causing exceptions (bug #19740)

  - API: Fixed an issue when virtual USB mass storage devices or virtual USB
       DVD drives are added while the VM is not running are by default not
       marked as hot-pluggable

  - API: Initial support for Python 3.10

  - API: Solaris OS types cleanup

  - Linux and Solaris hosts: Allow to mount shared folder if it is
       represented as a symlink on a host side (bug #17491)

  - Linux Host and Guest drivers: Introduced initial support for kernels
       5.18, 5.19 and RHEL 9.1 (bugs #20914, #20941)

  - Linux Host and Guest drivers: Better support for kernels built with
       clang compiler (bugs #20425 and #20998)

  - Solaris Guest Additions: General improvements in installer area

  - Solaris Guest Additions: Fixed guest screen resize in VMSVGA graphics
       configuration

  - Linux and Solaris Guest Additions: Fixed multi-screen handling in
       VBoxVGA and VBoxSVGA graphics configuration

  - Linux and Solaris Guest Additions: Added support for setting primary
       screen via VBoxManage

  - Linux and Solaris Guest Additions: Fixed X11 resources leak when
       resizing guest screens

  - Linux and Solaris Guest Additions: Fixed file descriptor leak when
       starting a process using guest control (bug #20902)

  - Linux and Solaris Guest Additions: Fixed guest control executing
       pro ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.1.36_k5.3.18_150300.59.90~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.1.36_k5.3.18_150300.59.90~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt", rpm:"virtualbox-kmp-preempt~6.1.36_k5.3.18_150300.59.90~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt-debuginfo", rpm:"virtualbox-kmp-preempt-debuginfo~6.1.36_k5.3.18_150300.59.90~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.1.36~lp153.2.33.2", rls:"openSUSELeap15.3"))) {
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