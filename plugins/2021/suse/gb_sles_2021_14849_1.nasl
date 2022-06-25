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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14849.1");
  script_cve_id("CVE-2014-7841", "CVE-2020-36385", "CVE-2021-20265", "CVE-2021-33033", "CVE-2021-3542", "CVE-2021-3609", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-42008", "CVE-2021-42739", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-12-02 03:22:29 +0000 (Thu, 02 Dec 2021)");
  script_version("2021-12-02T03:22:29+0000");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 16:13:00 +0000 (Fri, 08 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14849-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14849-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114849-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:14849-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-37159: hso_free_net_device in drivers/net/usb/hso.c called
 unregister_netdev without checking for the NETREG_REGISTERED state,
 leading to a use-after-free and a double free (bnc#1188601).

CVE-2021-3772: Fixed sctp vtag check in sctp_sf_ootb (bsc#1190351).

CVE-2021-3655: Missing size validations on inbound SCTP packets may have
 allowed the kernel to read uninitialized memory (bnc#1188563
 bnc#1192267).

CVE-2014-7841: The sctp_process_param function in
 net/sctp/sm_make_chunk.c in the SCTP implementation, when ASCONF is
 used, allowed remote attackers to cause a denial of service (NULL
 pointer dereference and system crash) via a malformed INIT chunk
 (bnc#904899 bnc#905100).

CVE-2021-20265: A flaw was found in the way memory resources were freed
 in the unix_stream_recvmsg function when a signal was pending. This flaw
 allowed an unprivileged local user to crash the system by exhausting
 available memory. The highest threat from this vulnerability is to
 system availability (bnc#1183089).

CVE-2021-42739: The firewire subsystem had a buffer overflow related to
 drivers/media/firewire/firedtv-avc.c and
 drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled
 bounds checking (bnc#1184673 bnc#1192036).

CVE-2021-33033: The Linux kernel has a use-after-free in cipso_v4_genopt
 in net/ipv4/cipso_ipv4.c because the CIPSO and CALIPSO refcounting for
 the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads to
 writing an arbitrary value (bnc#1186109 bnc#1188876).

CVE-2021-43389: There was an array-index-out-of-bounds flaw in the
 detach_capi_ctr function in drivers/isdn/capi/kcapi.c (bnc#1191958).

CVE-2021-42008: The decode_data function in drivers/net/hamradio/6pack.c
 had a slab out-of-bounds write. Input from a process that has the
 CAP_NET_ADMIN capability can lead to root access (bnc#1191315).

CVE-2021-38160: Data corruption or loss could be triggered by an
 untrusted device that supplies a buf->len value exceeding the buffer
 size in drivers/char/virtio_console.c (bsc#1190117)

CVE-2021-3640: Fixed a Use-After-Free vulnerability in function
 sco_sock_sendmsg() in the bluetooth stack (bsc#1188172).

CVE-2021-38198: arch/x86/kvm/mmu/paging_tmpl.h incorrectly computed the
 access permissions of a shadow page, leading to a missing guest
 protection page fault (bnc#1189262).

CVE-2021-3653: A flaw was found in the KVM's AMD code for supporting SVM
 nested virtualization. The flaw occurs when processing the VMCB (virtual
 machine control block) provided by the L1 guest to spawn/handle a nested
 guest (L2). Due to improper validation of the 'int_ctl' field, this
 issue could allow a malicious L1 to enable AVIC support (Advanced
 Virtual Interrupt Controller) for the L2 guest. As a result, the L2
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.132.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.132.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.132.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.132.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.132.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.132.1", rls:"SLES11.0SP4"))) {
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
