# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3033");
  script_cve_id("CVE-2023-1206", "CVE-2023-25775", "CVE-2023-3772", "CVE-2023-4004", "CVE-2023-4128", "CVE-2023-4132", "CVE-2023-4133", "CVE-2023-4147", "CVE-2023-4194", "CVE-2023-4273", "CVE-2023-4387", "CVE-2023-4459");
  script_tag(name:"creation_date", value:"2023-10-31 04:19:09 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:37 +0000 (Thu, 17 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-3033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=(EULEROS\-2\.0SP11|EULEROS\-2\.0SP11\-X86_64)");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3033");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3033");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-3033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30 may allow an unauthenticated user to potentially enable escalation of privilege via network access.(CVE-2023-25775)

A NULL pointer dereference flaw was found in vmxnet3_rq_cleanup in drivers/net/vmxnet3/vmxnet3_drv.c in the networking sub-component in vmxnet3 in the Linux Kernel. This issue may allow a local attacker with normal user privilege to cause a denial of service due to a missing sanity check during cleanup.(CVE-2023-4459)

A use-after-free flaw was found in vmxnet3_rq_alloc_rx_buf in drivers/net/vmxnet3/vmxnet3_drv.c in VMware's vmxnet3 ethernet NIC driver in the Linux Kernel. This issue could allow a local attacker to crash the system due to a double-free while cleaning up vmxnet3_rq_cleanup_all, which could also lead to a kernel information leak problem.(CVE-2023-4387)

A flaw was found in the exFAT driver of the Linux kernel. The vulnerability exists in the implementation of the file name reconstruction function, which is responsible for reading file name entries from a directory index and merging file name parts belonging to one file into a single long file name. Since the file name characters are copied into a stack variable, a local privileged attacker could use this flaw to overflow the kernel stack.(CVE-2023-4273)

A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue.(CVE-2023-4128)

A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to bypass network filters and gain unauthorized access to some resources. The original patches fixing CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits - a096ccca6e50 ('tun: tun_chr_open(): correctly initialize socket uid'), - 66b2c338adce ('tap: tap_open(): correctly initialize socket uid'), pass 'inode->i_uid' to sock_init_data_uid() as the last parameter and that turns out to not be accurate.(CVE-2023-4194)

A use-after-free flaw was found in the Linux kernel's Netfilter functionality when adding a rule with NFTA_RULE_CHAIN_ID. This flaw allows a local user to crash or escalate their privileges on the system.(CVE-2023-4147)

A use-after-free vulnerability was found in the siano smsusb module in the Linux kernel. The bug occurs during device initialization when the siano device is plugged in. This flaw allows a local user to crash the system, causing a denial of service condition.(CVE-2023-4132)

A use-after-free flaw was found in the Linux kernel's netfilter in the way a user triggers the nft_pipapo_remove function with the element, without a NFT_SET_EXT_KEY_END. This issue could allow a local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.41~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.41~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-magic", rpm:"python3-magic~5.41~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1002.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
