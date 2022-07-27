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
  script_oid("1.3.6.1.4.1.25623.1.0.854247");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-2475", "CVE-2021-35538", "CVE-2021-35540", "CVE-2021-35542", "CVE-2021-35545");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 12:35:00 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 01:02:06 +0000 (Wed, 27 Oct 2021)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2021:1393-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1393-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5TGGPXPQHCHAYI4TLQLUQ74AESTO2Y6W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2021:1393-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

     Version bump to 6.1.28 (released October 19 2021 by Oracle)

     This is a maintenance release. The following items were fixed and/or added:

  - VMM: Fixed guru meditation while booting nested-guests accessing debug
       registers under certain conditions

  - UI: Bug fixes for touchpad-based scrolling

  - VMSVGA: Fixed VM black screen issue on first resize after restoring from
       saved state (bug #20067)

  - VMSVGA: Fixed display corruption on Linux Mint (bug #20513)

  - Storage: Fixed a possible write error under certain circumstances when
       using VHD images (bug #20512)

  - Network: Multiple updates in virtio-net device support

  - Network: Disconnecting cable in saved VM state now is handled properly
       by virtio-net

  - Network: More administrative control over network ranges, see user manual

  - NAT: Fixed not rejecting TFTP requests with absolute pathnames (bug
       #20589)

  - Audio: Fixed VM session aborting after PC hibernation (bug #20516)

  - Audio: Fixed setting the line-in volume of the HDA emulation on modern
       Linux guests

  - Audio: Fixed resuming playback of the AC&#x27 97 emulation while a snapshot
       has been taken

  - API: Added bindings support for Python 3.9 (bug #20252)

  - API: Fixed rare hang of VM when changing settings at runtime

  - Linux host: Improved kernel modules installation detection which
       prevents unnecessary modules rebuild

  - Host Services: Shared Clipboard: Prevent guest clipboard reset when
       clipboard sharing is disabled (bug #20487)

  - Host Services: Shared Clipboard over VRDP: Fixed to continue working
       when guest service reconnects to host (bug #20366)

  - Host Services: Shared Clipboard over VRDP: Fixed preventing remote RDP
       client to hang when guest has no clipboard data to report

  - Linux Host and Guest: Introduced initial support for kernels 5.14 and
       5.15

  - Linux Host and Guest: Introduced initial support for RHEL 8.5 kernel

  - Windows Guest: Introduced Windows 11 guest support, including unattended
       installation

  - Fixes CVE-2021-35538, CVE-2021-35545, CVE-2021-35540, CVE-2021-35542,
       and CVE-2021-2475 (boo#1191869)

  - Use kernel_module_directory macro for kernel modules (boo#1191526)

  - Finish UsrMerge for VirtualBox components (boo#1191104).");

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

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.1.28_k5.3.18_59.27~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.1.28_k5.3.18_59.27~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt", rpm:"virtualbox-kmp-preempt~6.1.28_k5.3.18_59.27~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt-debuginfo", rpm:"virtualbox-kmp-preempt-debuginfo~6.1.28_k5.3.18_59.27~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.1.28~lp153.2.12.1", rls:"openSUSELeap15.3"))) {
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