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
  script_oid("1.3.6.1.4.1.25623.1.0.853441");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2020-14628", "CVE-2020-14629", "CVE-2020-14646", "CVE-2020-14647", "CVE-2020-14648", "CVE-2020-14649", "CVE-2020-14650", "CVE-2020-14673", "CVE-2020-14674", "CVE-2020-14675", "CVE-2020-14676", "CVE-2020-14677", "CVE-2020-14694", "CVE-2020-14695", "CVE-2020-14698", "CVE-2020-14699", "CVE-2020-14700", "CVE-2020-14703", "CVE-2020-14704", "CVE-2020-14707", "CVE-2020-14711", "CVE-2020-14712", "CVE-2020-14713", "CVE-2020-14714", "CVE-2020-14715");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-21 03:00:45 +0000 (Mon, 21 Sep 2020)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2020:1486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1486-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00068.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2020:1486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

  Update to Oracle version 6.1.14a.

  This minor update enables the building of libvirt again.

  Version update to 6.1.14 (released September 04 2020 by Oracle)

  File 'fix_virtio_build.patch' is added to fix a build problem. This is a
  maintenance release. The following items were fixed and/or added: GUI:
  Fixes file name changes in the File location field when creating Virtual
  Hard Disk (bug #19286) VMM: Fixed running VMs which failed to start with
  VERR_NEM_MISSING_KERNEL_API_2 when Hyper-V is used (bug #19779 and #19804)
  Audio: fix regression in HDA emulation introduced in 6.1.0 Shared
  Clipboard: Fixed a potential crash when copying HTML data (6.1.2
  regression, bug #19226) Linux host and guest: Linux kernel version 5.8
  support EFI: Fixed reading ISO9660 filesystems on attached media (6.1.0
  regression, bug #19682) EFI: Support booting from drives attached to the
  LsiLogic SCSI and SAS controller emulations

  Pseudo version bump to 6.1.13, which is NOT an Oracle release.

  Update VB sources to run under kernel 5.8.0+ with no modifications to
  the kernel. These sources are derived from r85883 of the Oracle svn
  repository. For operations with USB{2, 3}, the extension pack for revision
  140056 must be installed. Once Oracle releases 6.1.14, then the extension
  pack and VB itself will have the same revision number. File
  'fixes_for_5.8.patch' is removed as that part was fixed upstream. Fixes
  boo#1175201.

  Apply Oracle changes for kernel 5.8.

  Version bump to 6.1.12 (released July 14 2020 by Oracle)

  This is a maintenance release. The following items were fixed and/or
  added: File 'turn_off_cloud_net.patch' added. Fixes for CVE-2020-14628,
  CVE-2020-14646, CVE-2020-14647, CVE-2020-14649 CVE-2020-14713,
  CVE-2020-14674, CVE-2020-14675, CVE-2020-14676 CVE-2020-14677,
  CVE-2020-14699, CVE-2020-14711, CVE-2020-14629 CVE-2020-14703,
  CVE-2020-14704, CVE-2020-14648, CVE-2020-14650 CVE-2020-14673,
  CVE-2020-14694, CVE-2020-14695, CVE-2020-14698 CVE-2020-14700,
  CVE-2020-14712, CVE-2020-14707, CVE-2020-14714 CVE-2020-14715 boo#1174159.
  UI: Fixes for Log-Viewer search-backward icon Devices: Fixes and
  improvements for the BusLogic SCSI controller emulation Serial Port:
  Regression fixes in FIFO data handling Oracle Cloud Infrastructure
  integration: Experimental new type of network attachment, allowing local
  VM to act as if it was run in cloud API: improved resource management in
  the guest control functionality VBoxManage: fixed command option parsing
  for the 'snapshot edit' sub-command VB ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.1.14_k5.3.18_lp152.41~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.1.14_k5.3.18_lp152.41~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt", rpm:"virtualbox-kmp-preempt~6.1.14_k5.3.18_lp152.41~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt-debuginfo", rpm:"virtualbox-kmp-preempt-debuginfo~6.1.14_k5.3.18_lp152.41~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.1.14~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
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