# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3247");
  script_cve_id("CVE-2022-40982", "CVE-2022-45884", "CVE-2022-45887", "CVE-2022-45919", "CVE-2023-20588", "CVE-2023-21400", "CVE-2023-37453", "CVE-2023-3777", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-4015", "CVE-2023-4244", "CVE-2023-42753", "CVE-2023-42754", "CVE-2023-42756", "CVE-2023-45862", "CVE-2023-45863", "CVE-2023-45871", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-46813", "CVE-2023-4921", "CVE-2023-5178", "CVE-2023-5197", "CVE-2023-5717");
  script_tag(name:"creation_date", value:"2023-12-12 04:35:10 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-15 17:15:08 +0000 (Mon, 15 Jan 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-3247)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3247");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3247");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-3247 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the Linux kernel before 6.5.9, exploitable by local users with userspace access to MMIO registers. Incorrect access checking in the #VC handler and instruction emulation of the SEV-ES emulation of MMIO accesses could lead to arbitrary write access to kernel memory (and thus privilege escalation). This depends on a race condition through which userspace can replace an instruction before the #VC handler reads it.(CVE-2023-46813)

A heap out-of-bounds write vulnerability in the Linux kernel's Linux Kernel Performance Events (perf) component can be exploited to achieve local privilege escalation.If perf_read_group() is called while an event's sibling_list is smaller than its child's sibling_list, it can increment or write to memory locations outside of the allocated buffer.We recommend upgrading past commit 32671e3799ca2e4590773fd0e63aaa4229e50c06.(CVE-2023-5717)

A use-after-free vulnerability was found in drivers/nvme/target/tcp.c` in `nvmet_tcp_free_crypto` due to a logical bug in the NVMe-oF/TCP subsystem in the Linux kernel. This issue may allow a malicious user to cause a use-after-free and double-free problem, which may permit remote code execution or lead to local privilege escalation in case that the attacker already has local privileges.(CVE-2023-5178)

An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel before 6.5.3. A buffer size may not be adequate for frames larger than the MTU.(CVE-2023-45871)

An issue was discovered in lib/kobject.c in the Linux kernel before 6.2.3. With root access, an attacker can trigger a race condition that results in a fill_kobj_path out-of-bounds write.(CVE-2023-45863)

A flaw was found in the XFRM subsystem in the Linux kernel. The specific flaw exists within the processing of state filters, which can result in a read past the end of an allocated buffer. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, potentially leading to an information disclosure.(CVE-2023-39194)

An issue was discovered in drivers/usb/storage/ene_ub6250.c for the ENE UB6250 reader driver in the Linux kernel before 6.2.5. An object could potentially extend beyond the end of an allocation.(CVE-2023-45862)

A flaw was found in the Netfilter subsystem in the Linux kernel. The xt_u32 module did not validate the fields in the xt_u32 structure. This flaw allows a local privileged attacker to trigger an out-of-bounds read by setting the size fields with a value beyond the array boundaries, leading to a crash or information disclosure.(CVE-2023-39192)

A flaw was found in the Netfilter subsystem in the Linux kernel. The nfnl_osf_add_callback function did not validate the user mode controlled opt_num field. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1064.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
