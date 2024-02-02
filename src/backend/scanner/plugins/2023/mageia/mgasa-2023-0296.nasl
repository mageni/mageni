# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0296");
  script_cve_id("CVE-2023-1076", "CVE-2023-25775", "CVE-2023-4155", "CVE-2023-42754", "CVE-2023-42756", "CVE-2023-4921", "CVE-2023-5197");
  script_tag(name:"creation_date", value:"2023-10-23 04:11:50 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:37 +0000 (Thu, 17 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0296");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0296.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32297");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.11");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.12");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.14");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.15");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.4.16");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 6.4.16 and fixes or adds
mitigations for at least the following security issues:

A flaw was found in the Linux Kernel. The tun/tap sockets have their
socket UID hardcoded to 0 due to a type confusion in their
initialization function. While it will be often correct, as tuntap
devices require CAP_NET_ADMIN, it may not always be the case, e.g., a
non-root user only having that capability. This would make tun/tap
sockets being incorrectly treated in filtering/routing decisions,
possibly bypassing network filters. CVE-2023-1076

A flaw was found in KVM AMD Secure Encrypted Virtualization (SEV) in the
Linux kernel. A KVM guest using SEV-ES or SEV-SNP with multiple vCPUs
can trigger a double fetch race condition vulnerability and invoke the
`VMGEXIT` handler recursively. If an attacker manages to call the
handler multiple times, they can trigger a stack overflow and cause a
denial of service or potentially guest-to-host escape in kernel
configurations without stack guard pages (`CONFIG_VMAP_STACK`).
CVE-2023-4155

A use-after-free vulnerability in the Linux kernel's net/sched: sch_qfq
component can be exploited to achieve local privilege escalation. When
the plug qdisc is used as a class of the qfq qdisc, sending network
packets triggers use-after-free in qfq_dequeue() due to the incorrect
.peek handler of sch_plug and lack of error checking in agg_dequeue().
We recommend upgrading past commit
8fc134fee27f2263988ae38920bc03da416b03d8. CVE-2023-4921

A use-after-free vulnerability in the Linux kernel's netfilter:
nf_tables component can be exploited to achieve local privilege
escalation. Addition and removal of rules from chain bindings within the
same transaction causes leads to use-after-free. We recommend upgrading
past commit f15f29fd4779be8a418b66e9d52979bb6d6c2325. CVE-2023-5197

Improper access control in the Intel(R) Ethernet Controller RDMA driver
for linux before version 1.9.30 may allow an unauthenticated user to
potentially enable escalation of privilege via network access.
CVE-2023-25775

A NULL pointer dereference flaw was found in the Linux kernel ipv4
stack. The socket buffer (skb) was assumed to be associated with a
device before calling __ip_options_compile, which is not always the case
if the skb is re-routed by ipvs. This issue may allow a local user with
CAP_NET_ADMIN privileges to crash the system. CVE-2023-42754

A flaw was found in the Netfilter subsystem of the Linux kernel. A race
condition between IPSET_CMD_ADD and IPSET_CMD_SWAP can lead to a kernel
panic due to the invocation of `__ip_set_put` on a wrong `set`. This
issue may allow a local user to crash the system. CVE-2023-42756

For other upstream fixes in this update, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.4.16~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.4.16~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.4.16~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.4.16~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.4.16~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.4.16~3.mga9", rls:"MAGEIA9"))) {
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
