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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3192.1");
  script_cve_id("CVE-2018-9517", "CVE-2019-3874", "CVE-2019-3900", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-3753", "CVE-2021-3759", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2021-09-23T07:59:04+0000");
  script_tag(name:"last_modification", value:"2021-09-23 11:24:26 +0000 (Thu, 23 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-14 16:16:00 +0000 (Sat, 14 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3192-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3192-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213192-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3192-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2018-9517: Fixed possible memory corruption due to a use after free
 in pppol2tp_connect (bsc#1108488).

CVE-2019-3874: Fixed possible denial of service attack via SCTP socket
 buffer used by a userspace applications (bnc#1129898).

CVE-2019-3900: Fixed an infinite loop issue while handling incoming
 packets in handle_rx() (bnc#1133374).

CVE-2021-3640: Fixed a Use-After-Free vulnerability in function
 sco_sock_sendmsg() in the bluetooth stack (bsc#1188172).

CVE-2021-3653: Missing validation of the `int_ctl` VMCB field and allows
 a malicious L1 guest to enable AVIC support for the L2 guest.
 (bsc#1189399).

CVE-2021-3656: Missing validation of the `virt_ext` VMCB field and
 allows a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and
 VLS for the L2 guest (bsc#1189400).

CVE-2021-3679: A lack of CPU resource in tracing module functionality
 was found in the way user uses trace ring buffer in a specific way. Only
 privileged local users (with CAP_SYS_ADMIN capability) could use this
 flaw to starve the resources causing denial of service (bnc#1189057).

CVE-2021-3732: Mounting overlayfs inside an unprivileged user namespace
 can reveal files (bsc#1189706).

CVE-2021-3753: Fixed race out-of-bounds in virtual terminal handling
 (bsc#1190025).

CVE-2021-3759: Unaccounted ipc objects in Linux kernel could have lead
 to breaking memcg limits and DoS attacks (bsc#1190115).

CVE-2021-38160: Data corruption or loss could be triggered by an
 untrusted device that supplies a buf->len value exceeding the buffer
 size in drivers/char/virtio_console.c (bsc#1190117)

CVE-2021-38198: arch/x86/kvm/mmu/paging_tmpl.h incorrectly computes the
 access permissions of a shadow page, leading to a missing guest
 protection page fault (bnc#1189262).

CVE-2021-38204: drivers/usb/host/max3421-hcd.c allowed physically
 proximate attackers to cause a denial of service (use-after-free and
 panic) by removing a MAX-3421 USB device in certain situations
 (bnc#1189291).

The following non-security bugs were fixed:

ACPI: NFIT: Fix support for virtual SPA ranges (git-fixes).

ALSA: seq: Fix racy deletion of subscriber (git-fixes).

ASoC: cs42l42: Do not allow SND_SOC_DAIFMT_LEFT_J (git-fixes).

ASoC: cs42l42: Fix inversion of ADC Notch Switch control (git-fixes).

ASoC: cs42l42: Remove duplicate control for WNF filter frequency
 (git-fixes).

Bluetooth: Move shutdown callback before flushing tx and rx queue
 (git-fixes).

Bluetooth: add timeout sanity check to hci_inquiry (git-fixes).

Bluetooth: fix repeated calls to sco_sock_kill (git-fixes).

Bluetooth: increase BTNAMSIZ to 21 chars to fix potential buffer
 overflow (git-fixes).

Bluetooth: sco: prevent information leak in sco_conn_defer_accept()
 (git-fixes).

KVM: SVM: Call SEV Guest ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
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
