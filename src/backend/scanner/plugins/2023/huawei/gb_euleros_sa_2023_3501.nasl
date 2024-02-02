# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3501");
  script_cve_id("CVE-2023-1206", "CVE-2023-21400", "CVE-2023-3772", "CVE-2023-4128", "CVE-2023-4194", "CVE-2023-4206", "CVE-2023-4207", "CVE-2023-4208", "CVE-2023-42753", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2023-12-22 04:20:17 +0000 (Fri, 22 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-3501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3501");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-3501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An array indexing vulnerability was found in the netfilter subsystem of the Linux kernel. A missing macro could lead to a miscalculation of the `h->nets` array offset, providing attackers with the primitive to arbitrarily increment/decrement a memory buffer out-of-bound. This issue may allow a local user to crash the system or potentially escalate their privileges on the system.(CVE-2023-42753)

A use-after-free vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited to achieve local privilege escalation.When the plug qdisc is used as a class of the qfq qdisc, sending network packets triggers use-after-free in qfq_dequeue() due to the incorrect .peek handler of sch_plug and lack of error checking in agg_dequeue().We recommend upgrading past commit 8fc134fee27f2263988ae38920bc03da416b03d8.(CVE-2023-4921)

A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to achieve local privilege escalation.When u32_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free.We recommend upgrading past commit 3044b16e7c6fe5d24b1cdbcf1bd0a9d92d1ebd81.(CVE-2023-4208)

A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to achieve local privilege escalation.When fw_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free.We recommend upgrading past commit 76e42ae831991c828cffa8c37736ebfb831ad5ec.(CVE-2023-4207)

A use-after-free vulnerability in the Linux kernel's net/sched: cls_route component can be exploited to achieve local privilege escalation.When route4_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free.We recommend upgrading past commit b80b829e9e2c1b3f7aae34855e04d8f6ecaf13c8.(CVE-2023-4206)

A use-after-free vulnerability in the Linux kernel's net/sched: sch_hfsc (HFSC qdisc traffic control) component can be exploited to achieve local privilege escalation.If a class with a link-sharing curve (i.e. with the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1620.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1620.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1620.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1620.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1620.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
