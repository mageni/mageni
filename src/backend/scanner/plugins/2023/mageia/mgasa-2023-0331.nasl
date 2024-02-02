# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0331");
  script_cve_id("CVE-2020-26555", "CVE-2023-25775", "CVE-2023-34319", "CVE-2023-34324", "CVE-2023-3772", "CVE-2023-3773", "CVE-2023-39189", "CVE-2023-4155", "CVE-2023-46813", "CVE-2023-5090", "CVE-2023-5178", "CVE-2023-5345", "CVE-2023-5633", "CVE-2023-5717", "CVE-2023-6176");
  script_tag(name:"creation_date", value:"2023-11-30 04:12:11 +0000 (Thu, 30 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-15 17:15:08 +0000 (Mon, 15 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2023-0331)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0331");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0331.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32538");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.5.11");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0331 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 6.5.11 and fixes or adds
mitigations for at least the following security issues:

A use-after-free vulnerability was found in drivers/nvme/target/tcp.c`
in `nvmet_tcp_free_crypto` due to a logical bug in the NVMe-oF/TCP
subsystem in the Linux kernel. This issue may allow a malicious user to
cause a use-after-free and double-free problem, which may permit remote
code execution or lead to local privilege escalation in case that the
attacker already has local privileges. (CVE-2023-5178)

x86: KVM: SVM: always update the x2avic msr interception:
The following problem exists since x2avic was enabled in the KVM:
svm_set_x2apic_msr_interception is called to enable the interception of
the x2apic msrs.
In particular it is called at the moment the guest resets its apic.
Assuming that the guest's apic is in x2apic mode, the reset will bring
it back to the xapic mode.
The svm_set_x2apic_msr_interception however has an erroneous check for
'!apic_x2apic_mode()' which prevents it from doing anything in this case.
As a result of this, all x2apic msrs are left unintercepted, and that
exposes the bare metal x2apic (if enabled) to the guest.
Removing the erroneous '!apic_x2apic_mode()' check fixes that.
(CVE-2023-5090)

In unprivileged Xen guests event handling can cause a deadlock with
Xen console handling. The evtchn_rwlock and the hvc_lock are taken in
opposite sequence in __hvc_poll() and in Xen console IRQ handling.
This is fixed by xen/events: replace evtchn_rwlock with RCU
(CVE-2023-34324)

A use-after-free vulnerability in the Linux kernel's fs/smb/client
component can be exploited to achieve local privilege escalation. In
case of an error in smb3_fs_context_parse_param, ctx->password was freed
but the field was not set to NULL which could lead to double free. We
recommend upgrading past commit e6e43b8aa7cd3c3af686caf0c2e11819a886d705
(CVE-2023-5345)

A flaw was found in the Netfilter subsystem in the Linux kernel. The
nfnl_osf_add_callback function did not validate the user mode controlled
opt_num field. This flaw allows a local privileged (CAP_NET_ADMIN)
attacker to trigger an out-of-bounds read, leading to a crash or
information disclosure. (CVE-2023-39189)

The reference count changes made as part of the CVE-2023-33951 and
CVE-2023-33952 fixes exposed a use-after-free flaw in the way memory
objects were handled when they were being used to store a surface. When
running inside a VMware guest with 3D acceleration enabled, a local,
unprivileged user could potentially use this flaw to escalate their
privileges. (CVE-2023-5633)

A heap out-of-bounds write vulnerability in the Linux kernel's Linux
Kernel Performance Events (perf) component can be exploited to achieve
local privilege escalation. If perf_read_group() is called while an
event's sibling_list is smaller than its child's sibling_list, it can
increment or write to memory locations ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.5.11~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.5.11~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.5.11~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.5.11~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.5.11~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.5.11~2.mga9", rls:"MAGEIA9"))) {
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
