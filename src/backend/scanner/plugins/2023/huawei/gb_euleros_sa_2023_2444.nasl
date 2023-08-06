# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2444");
  script_cve_id("CVE-2018-1128", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-18885", "CVE-2019-19039", "CVE-2019-9444", "CVE-2020-0066", "CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0433", "CVE-2020-12655", "CVE-2020-12888", "CVE-2020-14416", "CVE-2020-25284", "CVE-2020-25670", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-27066", "CVE-2020-2732", "CVE-2020-28374", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36322", "CVE-2020-36557", "CVE-2020-36558", "CVE-2020-4788", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-22555", "CVE-2021-33098", "CVE-2021-33655", "CVE-2021-33656", "CVE-2021-3564", "CVE-2021-3715", "CVE-2021-3923", "CVE-2021-39634", "CVE-2021-39648", "CVE-2021-4037", "CVE-2021-4155", "CVE-2022-0812", "CVE-2022-1184", "CVE-2022-1679", "CVE-2022-20166", "CVE-2022-20368", "CVE-2022-20565", "CVE-2022-20572", "CVE-2022-2503", "CVE-2022-2588", "CVE-2022-2663", "CVE-2022-2873", "CVE-2022-29581", "CVE-2022-2964", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-32296", "CVE-2022-3424", "CVE-2022-34918", "CVE-2022-3524", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-36123", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-3903", "CVE-2022-39188", "CVE-2022-40768", "CVE-2022-41218", "CVE-2022-4129", "CVE-2022-41850", "CVE-2022-4269", "CVE-2022-42703", "CVE-2022-43750", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-1281", "CVE-2023-1380", "CVE-2023-1382", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-28328", "CVE-2023-28772");
  script_tag(name:"creation_date", value:"2023-07-25 08:38:57 +0000 (Tue, 25 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-07 06:15:00 +0000 (Tue, 07 Jan 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-2444)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2444");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2444");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-2444 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition and resultant use-after-free in certain situations where a report is received while copying a report->value is in progress.(CVE-2022-41850)

mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.(CVE-2022-42703)

A memory leak flaw was found in bnx2x_tpa_stop in drivers
et/ethernet/broadcom/bnx2x/bnx2x_cmn.c in the bnx2x sub-component in the Linux Kernel. This flaw may allow a local attacker to cause a denial of service.(CVE-2022-3542)

A data race problem was found in sk->sk_prot in the network subsystem in ipv6 in the Linux kernel. This issue occurs while some functions access critical data, leading to a denial of service.(CVE-2022-3567)

A vulnerability was found in the tcp subsystem in the Linux Kernel, due to a data race around icsk->icsk_af_ops. This issue could allow an attacker to leak internal kernel information.(CVE-2022-3566)

An out-of-bounds memory write flaw in the Linux kernel's USB Monitor component was found in how a user with access to the /dev/usbmon can trigger it by an incorrect write to the memory of the usbmon. This flaw allows a local user to crash or potentially escalate their privileges on the system.(CVE-2022-43750)

A vulnerability was found in area_cache_get in drivers et/ethernet,etronome,fp,fpcore,fp_cppcore.c in the Netronome Flow Processor (NFP) driver in the Linux kernel. This flaw allows a manipulation that may lead to a use-after-free issue.(CVE-2022-3545)

A memory leak flaw was found in the Linux kernel's IPv6 functionality in how a user triggers the setsockopt of the IPV6_ADDRFORM and IPV6_DSTOPTS type. This flaw allows a user to crash the system if the setsockopt function is being called simultaneously with the IPV6_ADDRFORM type and other processes with the IPV6_DSTOPTS type. This issue is unlikely to happen unless a local process triggers IPV6_ADDRFORM.(CVE-2022-3524)

A use-after-free flaw was found in the Linux kernel's L2CAP bluetooth functionality in how a user triggers a race condition by two malicious flows in the L2CAP bluetooth packets. This flaw allows a local or bluetooth connection user to crash the system or potentially escalate privileges.(CVE-2022-3564)

A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed) into a child qdisc. This flaw allows a local, unprivileged user to to disclose sensitive information or crash the system, causing a denial of service.(CVE-2022-3586)

A use-after-free flaw was found in the Linux kernel's ISDN over IP tunnel functionality in how a local user triggers the release_card() function called from l1oip_cleanup(). This flaw allows a local user to crash or potentially escalate their ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_204", rls:"EULEROSVIRT-3.0.6.6"))) {
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
