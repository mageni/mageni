# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854059");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-2409", "CVE-2021-2442", "CVE-2021-2443", "CVE-2021-2454");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 03:02:51 +0000 (Wed, 11 Aug 2021)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2021:1114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1114-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XVEDYTCL4HZ2BYHJLWW2ON7AOWMAGAVD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2021:1114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

     Version bump to 6.1.26 (released July 28 2021 by Oracle)

     This is a maintenance release. The following items were fixed and/or added:

  - VMSVGA: fixed VM screen artifacts after restoring from saved state (bug
       #20067)

  - Storage: Fixed audio endianness for certain CUE sheet CD/DVD images.

  - VBoxHeadless: Running VM will save its state on host shutdown

  - VBoxManage: Fix OS detection for Ubuntu 20.10 ISO with unattended install

  - Linux Additions: Fixed mouse pointer offsetting issue for VMSVGA
       graphics adapter in multi-monitor VM setup (6.1.24 regression)

     Version bump to 6.1.24 (released July 20 2021 by Oracle)

     This is a maintenance release. The following items were fixed and/or added:

  - Storage: Fixed starting a VM if a device is attached to a VirtIO SCSI
       port higher than 30 (bug #20213)

  - Storage: Improvement to DVD medium change signaling

  - Serial: Fixed a the guest missing interrupts under certain circumstances
       (6.0 regression, bug #18668)

  - Audio: Multiple fixes and enhancements

  - Network: Fixed connectivity issue with virtio-net after resuming VM with
       disconnected link

  - Network: Fixed UDP GSO fragmentation issue with missing 8 bytes of
       payload at the end of the first fragment

  - API: Fixed VM configuration for recent Windows Server versions

  - Extension Pack: Fixed issues with USB webcam pass-through on Linux

  - Host and guest driver: Fix small memory leak (bug #20280)

  - Linux host and guest: Support kernel version 5.13 (bug #20456)

  - Linux host and guest: Introduce support for SUSE SLES/SLED 15 SP3
       kernels (bug #20396)

  - Linux host: Installer will not attempt to build kernel modules if system
       already has them installed and modules versions match current version

  - Guest Additions: Fixed crash on using shared clipboard (bug #19165)

  - Linux Guest Additions: Introduce support for Ubuntu specific kernels
       (bug #20325)

  - Solaris guest: Increased default memory and disk sizes

  - EFI: Support network booting with the E1000 network controller emulation

  - EFI: Stability improvements (bug #20090)

  - This release fixes boo#1188535, VUL-0: CVE-2021-2454, boo#1188536,
       VUL-0: CVE-2021-2409, boo#1188537, VUL-0: CVE-2021-2442, and
       boo#1188538, VUL-0: CVE-2021-2443.

  - Add vboximg-mount to packaging. boo#1188045.

  - Fixed CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT problem with kernel 5.13 as
       shown in boo#1188105.

  - D ...

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

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.1.26_k5.3.18_lp152.84~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.1.26_k5.3.18_lp152.84~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt", rpm:"virtualbox-kmp-preempt~6.1.26_k5.3.18_lp152.84~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt-debuginfo", rpm:"virtualbox-kmp-preempt-debuginfo~6.1.26_k5.3.18_lp152.84~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.1.26~lp152.2.35.1", rls:"openSUSELeap15.2"))) {
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