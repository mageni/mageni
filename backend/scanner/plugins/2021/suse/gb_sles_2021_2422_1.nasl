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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2422.1");
  script_cve_id("CVE-2020-24588", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-33200", "CVE-2021-33624", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-23 10:28:28 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2422-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212422-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-22555: A heap out-of-bounds write was discovered in
 net/netfilter/x_tables.c (bnc#1188116).

CVE-2021-33909: Extremely large seq buffer allocations in seq_file could
 lead to buffer underruns and code execution (bsc#1188062).

CVE-2021-3609: A use-after-free in can/bcm could have led to privilege
 escalation (bsc#1187215).

CVE-2021-33624: In kernel/bpf/verifier.c a branch can be mispredicted
 (e.g., because of type confusion) and consequently an unprivileged BPF
 program can read arbitrary memory locations via a side-channel attack,
 aka CID-9183671af6db (bnc#1187554).

CVE-2021-0605: In pfkey_dump of af_key.c, there is a possible
 out-of-bounds read due to a missing bounds check. This could lead to
 local information disclosure in the kernel with System execution
 privileges needed. User interaction is not needed for exploitation
 (bnc#1187601).

CVE-2021-0512: In __hidinput_change_resolution_multipliers of
 hid-input.c, there is a possible out of bounds write due to a heap
 buffer overflow. This could lead to local escalation of privilege with
 no additional execution privileges needed. User interaction is not
 needed for exploitation (bnc#1187595).

CVE-2020-26558: Bluetooth LE and BR/EDR secure pairing in Bluetooth Core
 Specification 2.1 may permit a nearby man-in-the-middle attacker to
 identify the Passkey used during pairing (in the Passkey authentication
 procedure) by reflection of the public key and the authentication
 evidence of the initiating device, potentially permitting this attacker
 to complete authenticated pairing with the responding device using the
 correct Passkey for the pairing session. The attack methodology
 determines the Passkey value one bit at a time (bnc#1179610 bnc#1186463).

CVE-2021-34693: net/can/bcm.c allowed local users to obtain sensitive
 information from kernel stack memory because parts of a data structure
 are uninitialized (bnc#1187452).

CVE-2020-36385: An issue was discovered in
 drivers/infiniband/core/ucma.c has a use-after-free because the ctx is
 reached via the ctx_list in some ucma_migrate_id situations where
 ucma_close is called, aka CID-f5449e74802c (bnc#1187050).

CVE-2021-0129: Improper access control in BlueZ may have allowed an
 authenticated user to potentially enable information disclosure via
 adjacent access (bnc#1186463).

CVE-2020-36386: An issue was discovered net/bluetooth/hci_event.c has a
 slab out-of-bounds read in hci_extended_inquiry_result_evt, aka
 CID-51c19bf3d5cf (bnc#1187038).

CVE-2020-24588: The 802.11 standard that underpins Wi-Fi Protected
 Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't
 require that the A-MSDU flag in the plaintext QoS header field is
 authenticated. Against devices that support receiving non-SSP ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE OpenStack Cloud Crowbar 9, SUSE OpenStack Cloud 9, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise High Availability 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.80.1", rls:"SLES12.0SP4"))) {
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
