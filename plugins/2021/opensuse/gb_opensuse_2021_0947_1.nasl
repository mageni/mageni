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
  script_oid("1.3.6.1.4.1.25623.1.0.853901");
  script_version("2021-07-06T12:11:22+0000");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3491");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-02 03:01:09 +0000 (Fri, 02 Jul 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:0947-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0947-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M3WU4VH2HXVC3VLST5RWUW7LUFNSUEIN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:0947-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 RT kernel was updated to receive various
     security and bugfixes.


     The following security bugs were fixed:

  - CVE-2021-33200: Enforcing incorrect limits for pointer arithmetic
       operations by the BPF verifier could be abused to perform out-of-bounds
       reads and writes in kernel memory (bsc#1186484).

  - CVE-2021-33034: Fixed a use-after-free when destroying an hci_chan. This
       could lead to writing an arbitrary values. (bsc#1186111)

  - CVE-2020-26139: Fixed a denial-of-service when an Access Point (AP)
       forwards EAPOL frames to other clients even though the sender has not
       yet successfully authenticated to the AP. (bnc#1186062)

  - CVE-2021-23134: A Use After Free vulnerability in nfc sockets allowed
       local attackers to elevate their privileges. (bnc#1186060)

  - CVE-2021-3491: Fixed a potential heap overflow in mem_rw(). This
       vulnerability is related to the PROVIDE_BUFFERS operation, which allowed
       the MAX_RW_COUNT limit to be bypassed (bsc#1185642).

  - CVE-2021-32399: Fixed a race condition when removing the HCI controller
       (bnc#1184611).

  - CVE-2020-24586: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that received fragments be cleared from memory after
       (re)connecting to a network. Under the right circumstances this can be
       abused to inject arbitrary network packets and/or exfiltrate user data
       (bnc#1185859).

  - CVE-2020-24587: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that all fragments of a frame are encrypted under the same key.
       An adversary can abuse this to decrypt selected fragments when another
       device sends fragmented frames and the WEP, CCMP, or GCMP encryption key
       is periodically renewed (bnc#1185859 bnc#1185862).

  - CVE-2020-26147: The WEP, WPA, WPA2, and WPA3 implementations reassemble
       fragments, even though some of them were sent in plaintext. This
       vulnerability can be abused to inject packets and/or exfiltrate selected
       fragments when another device sends fragmented frames and the WEP, CCMP,
       or GCMP data-confidentiality protocol is used (bnc#1185859).

  - CVE-2020-24588: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that the A-MSDU flag in the plaintext QoS header fie ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt_debug", rpm:"cluster-md-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt_debug-debuginfo", rpm:"cluster-md-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt_debug", rpm:"dlm-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt_debug-debuginfo", rpm:"dlm-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt_debug", rpm:"gfs2-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt_debug-debuginfo", rpm:"gfs2-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-extra", rpm:"kernel-rt_debug-extra~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-extra-debuginfo", rpm:"kernel-rt_debug-extra-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt_debug", rpm:"kselftests-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt_debug-debuginfo", rpm:"kselftests-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt_debug", rpm:"ocfs2-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt_debug-debuginfo", rpm:"ocfs2-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt_debug", rpm:"reiserfs-kmp-rt_debug~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt_debug-debuginfo", rpm:"reiserfs-kmp-rt_debug-debuginfo~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.3.18~lp152.3.14.1", rls:"openSUSELeap15.2"))) {
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