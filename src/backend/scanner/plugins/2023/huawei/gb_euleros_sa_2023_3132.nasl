# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3132");
  script_cve_id("CVE-2022-4269", "CVE-2023-0458", "CVE-2023-1206", "CVE-2023-2124", "CVE-2023-2176", "CVE-2023-2177", "CVE-2023-2269", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3161", "CVE-2023-32233", "CVE-2023-3268", "CVE-2023-33203", "CVE-2023-3390", "CVE-2023-34256", "CVE-2023-35001", "CVE-2023-35788", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3772", "CVE-2023-3776", "CVE-2023-4128", "CVE-2023-4194");
  script_tag(name:"creation_date", value:"2023-11-09 04:28:52 +0000 (Thu, 09 Nov 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:27 +0000 (Mon, 31 Jul 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-3132)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3132");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3132");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-3132 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue.(CVE-2023-4128)

A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to bypass network filters and gain unauthorized access to some resources. The original patches fixing CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits - a096ccca6e50 ('tun: tun_chr_open(): correctly initialize socket uid'), - 66b2c338adce ('tap: tap_open(): correctly initialize socket uid'), pass 'inode->i_uid' to sock_init_data_uid() as the last parameter and that turns out to not be accurate.(CVE-2023-4194)

A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to achieve local privilege escalation.If tcf_change_indev() fails, fw_set_parms() will immediately return an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can control the reference counter and set it to zero, they can cause the reference to be freed, leading to a use-after-free vulnerability.We recommend upgrading past commit 0323bce598eea038714f941ce2b22541c46d488f.(CVE-2023-3776)

A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to achieve local privilege escalation.If tcf_change_indev() fails, u32_set_parms() will immediately return an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can control the reference counter and set it to zero, they can cause the reference to be freed, leading to a use-after-free vulnerability.We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.(CVE-2023-3609)

A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in xfrm_update_ae_params(), leading to a possible kernel crash and denial of service.(CVE-2023-3772)

An out-of-bounds write vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited to achieve local privilege escalation.The qfq_change_agg() function in net/sched/sch_qfq.c allows an out-of-bounds write because lmax is updated according to packet sizes without bounds checks.We recommend upgrading past commit 3e337087c3b5805fe0b8a46ba622a962880b5d64.(CVE-2023-3611)

Linux Kernel nftables Out-Of-Bounds Read/Write Vulnerability, nft_byteorder poorly handled vm register contents when CAP_NET_ADMIN is in any user or network namespace(CVE-2023-35001)

A use-after-free vulnerability was found in the Linux kernel's netfilter subsystem in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h1489.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
