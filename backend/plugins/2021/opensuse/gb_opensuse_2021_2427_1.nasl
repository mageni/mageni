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
  script_oid("1.3.6.1.4.1.25623.1.0.854011");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-24588", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-33200", "CVE-2021-33624", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-22 03:01:48 +0000 (Thu, 22 Jul 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:2427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2427-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HJIMD6XIKYMKE35TUYXKKYPX4737LEVU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:2427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various
     security and bugfixes.

     The following security bugs were fixed:

     - CVE-2021-22555: Fixed an heap out-of-bounds write in
       net/netfilter/x_tables.c that could allow local provilege escalation.
       (bsc#1188116)
     - CVE-2021-33624: Fixed a bug which allows unprivileged BPF program to
       leak the contents of arbitrary kernel memory (and therefore, of all
       physical memory) via a side-channel. (bsc#1187554)
     - CVE-2021-0605: Fixed an out-of-bounds read which could lead to local
       information disclosure in the kernel with System execution privileges
       needed. (bsc#1187601)
     - CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to
       local escalation of privilege with no additional execution privileges
       needed. (bsc#1187595)
     - CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure
       pairing that could permit a nearby man-in-the-middle attacker to
       identify the Passkey used during pairing. (bnc#1179610)
     - CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local
       users to obtain sensitive information from kernel stack memory because
       parts of a data structure are uninitialized. (bsc#1187452)
     - CVE-2021-0129: Fixed an improper access control in BlueZ that may have
       allowed an authenticated user to potentially enable information
       disclosure via adjacent access. (bnc#1186463)
     - CVE-2020-36386: Fixed an out-of-bounds read in
       hci_extended_inquiry_result_evt. (bsc#1187038)
     - CVE-2020-24588: Fixed a bug that could allow an adversary to abuse
       devices that support receiving non-SSP A-MSDU frames to inject arbitrary
       network packets. (bsc#1185861 bsc#1185863)
     - CVE-2021-33909: Fixed an out-of-bounds write in the filesystem layer
       that allows to andobtain full root privileges. (bsc#1188062)
     - CVE-2021-3609: Fixed a race condition in the CAN BCM networking protocol
       which allows for local privilege escalation. (bsc#1187215)
     - CVE-2020-36385: Fixed a use-after-free flaw in ucma.c which allows for
       local privilege escalation. (bsc#1187050)
     - CVE-2021-33200: Fix leakage of uninitialized bpf stack under
       speculation. (bsc#1186484)

     The following non-security bugs were fixed:

     - af_packet: fix the tx skb protocol in raw sockets with ETH_P_ALL
       (bsc#1176081).
     - kabi: preserve struct header_ops after bsc#1176081 fix (bsc#1176081).
     - net: Do not set transport offset to invalid value (bsc#1176081) ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel-debuginfo", rpm:"kernel-vanilla-devel-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-livepatch-devel", rpm:"kernel-vanilla-livepatch-devel~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base", rpm:"kernel-kvmsmall-base~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base-debuginfo", rpm:"kernel-kvmsmall-base-debuginfo~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-man", rpm:"kernel-zfcpdump-man~4.12.14~197.99.1", rls:"openSUSELeap15.3"))) {
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