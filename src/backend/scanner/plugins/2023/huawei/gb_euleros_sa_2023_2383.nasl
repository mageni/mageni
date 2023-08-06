# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2383");
  script_cve_id("CVE-2022-29901", "CVE-2023-0458", "CVE-2023-2162", "CVE-2023-2176", "CVE-2023-2177", "CVE-2023-2194", "CVE-2023-2248", "CVE-2023-2269", "CVE-2023-2483", "CVE-2023-31436", "CVE-2023-32233");
  script_tag(name:"creation_date", value:"2023-07-17 04:14:57 +0000 (Mon, 17 Jul 2023)");
  script_version("2023-07-17T05:05:06+0000");
  script_tag(name:"last_modification", value:"2023-07-17 05:05:06 +0000 (Mon, 17 Jul 2023)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 21:15:00 +0000 (Mon, 15 May 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-2383)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2383");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2383");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-2383 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.(CVE-2023-32233)

A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.(CVE-2023-2162)

A denial of service problem was found, due to a possible recursive locking scenario, resulting in a deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-component.(CVE-2023-2269)

A null pointer dereference issue was found in the sctp network protocol in net/sctp/stream_sched.c in Linux Kernel. If stream_in allocation is failed, stream_out is freed which would further be accessed. A local user could use this flaw to crash the system or potentially cause a denial of service.(CVE-2023-2177)

A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be used to leak the contents. We recommend upgrading past version 6.1.8 or commit 739790605705ddcf18f21782b9c99ad7d53a8c11(CVE-2023-0458)

A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA in the Linux Kernel. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem to crash the system or escalation of privilege.(CVE-2023-2176)

An out-of-bounds write vulnerability was found in the Linux kernel's SLIMpro I2C device driver. The userspace 'data->block[0]' variable was not capped to a number between 0-255 and was used as the size of a memcpy, possibly writing beyond the end of dma_buffer. This flaw could allow a local privileged user to crash the system or potentially achieve code execution.(CVE-2023-2194)

An out-of-bounds memory access flaw was found in the Linux kernel's traffic control (QoS) subsystem in how a user triggers the qfq_change_class function with an incorrect MTU value of the network device used as lmax. This flaw allows a local user to crash or potentially escalate their privileges on the system.(CVE-2023-2248)

A race condition vulnerability was found in the Linux kernel's Qualcomm EMAC Gigabit Ethernet Controller when the user physically removes the device before cleanup in the emac_remove function. This flaw can eventually result in a use-after-free issue, possibly leading to a system crash or other undefined behaviors.(CVE-2023-2483)

qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write because lmax can exceed QFQ_MIN_LMAX.(CVE-2023-31436)

Intel microprocessor ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1543.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1543.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1543.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1543.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1543.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
