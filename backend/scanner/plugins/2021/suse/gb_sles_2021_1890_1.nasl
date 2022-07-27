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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1890.1");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3491");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:29:57+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 19:12:00 +0000 (Fri, 11 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1890-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211890-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-33200: Enforcing incorrect limits for pointer arithmetic
 operations by the BPF verifier could be abused to perform out-of-bounds
 reads and writes in kernel memory (bsc#1186484).

CVE-2021-33034: Fixed a use-after-free when destroying an hci_chan. This
 could lead to writing an arbitrary values. (bsc#1186111)

CVE-2020-26139: Fixed a denial-of-service when an Access Point (AP)
 forwards EAPOL frames to other clients even though the sender has not
 yet successfully authenticated to the AP. (bnc#1186062)

CVE-2021-23134: A Use After Free vulnerability in nfc sockets allowed
 local attackers to elevate their privileges. (bnc#1186060)

CVE-2021-3491: Fixed a potential heap overflow in mem_rw(). This
 vulnerability is related to the PROVIDE_BUFFERS operation, which allowed
 the MAX_RW_COUNT limit to be bypassed (bsc#1185642).

CVE-2021-32399: Fixed a race condition when removing the HCI controller
 (bnc#1184611).

CVE-2020-24586: The 802.11 standard that underpins Wi-Fi Protected
 Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't
 require that received fragments be cleared from memory after
 (re)connecting to a network. Under the right circumstances this can be
 abused to inject arbitrary network packets and/or exfiltrate user data
 (bnc#1185859).

CVE-2020-24587: The 802.11 standard that underpins Wi-Fi Protected
 Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't
 require that all fragments of a frame are encrypted under the same key.
 An adversary can abuse this to decrypt selected fragments when another
 device sends fragmented frames and the WEP, CCMP, or GCMP encryption key
 is periodically renewed (bnc#1185859 bnc#1185862).

CVE-2020-26147: The WEP, WPA, WPA2, and WPA3 implementations reassemble
 fragments, even though some of them were sent in plaintext. This
 vulnerability can be abused to inject packets and/or exfiltrate selected
 fragments when another device sends fragmented frames and the WEP, CCMP,
 or GCMP data-confidentiality protocol is used (bnc#1185859).

CVE-2020-24588: The 802.11 standard that underpins Wi-Fi Protected
 Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't
 require that the A-MSDU flag in the plaintext QoS header field is
 authenticated. Against devices that support receiving non-SSP A-MSDU
 frames (which is mandatory as part of 802.11n), an adversary can abuse
 this to inject arbitrary network packets. (bnc#1185861)

CVE-2020-26145: An issue was discovered with Samsung Galaxy S3 i9305
 4.4.4 devices. The WEP, WPA, WPA2, and WPA3 implementations accept
 second (or subsequent) broadcast fragments even when sent in plaintext
 and process them as full unfragmented frames. An adversary can abuse
 this to inject arbitrary network packets ind... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE MicroOS 5.0, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Availability 15-SP2");

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

if(release == "SLES15.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.67.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.67.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.67.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.67.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.67.3.9.30.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.67.3", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.67.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.67.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.67.2", rls:"SLES15.0SP2"))){
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
