# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4665.1");
  script_cve_id("CVE-2021-26345", "CVE-2021-46766", "CVE-2021-46774", "CVE-2022-23820", "CVE-2022-23830", "CVE-2023-20519", "CVE-2023-20521", "CVE-2023-20526", "CVE-2023-20533", "CVE-2023-20566", "CVE-2023-20592");
  script_tag(name:"creation_date", value:"2023-12-07 04:20:31 +0000 (Thu, 07 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 18:26:30 +0000 (Fri, 01 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4665-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234665-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2023:4665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:
Update AMD ucode to 20231030 (bsc#1215831):

CVE-2022-23820: Failure to validate the AMD SMM communication buffer may allow an attacker to corrupt the SMRAM potentially leading to arbitrary code execution.
CVE-2021-46774: Insufficient input validation in ABL may enable a privileged attacker to perform arbitrary DRAM writes, potentially resulting in code execution and privilege escalation.
CVE-2023-20533: Insufficient DRAM address validation in System Management Unit (SMU) may allow an attacker using DMA to read/write from/to invalid DRAM address potentially resulting in denial-of-service.
0 CVE-2023-20519: A Use-After-Free vulnerability in the management of an SNP guest context page may allow a malicious hypervisor to masquerade as the guest's migration agent resulting in a potential loss of guest integrity.
CVE-2023-20566: Improper address validation in ASP with SNP enabled may potentially allow an attacker to compromise guest memory integrity.
CVE-2023-20521: TOCTOU in the ASP Bootloader may allow an attacker with physical access to tamper with SPI ROM records after memory content verification, potentially leading to loss of confidentiality or a denial of service.
CVE-2021-46766: Improper clearing of sensitive data in the ASP Bootloader may expose secret keys to a privileged attacker accessing ASP SRAM, potentially leading to a loss of confidentiality.
CVE-2022-23830: SMM configuration may not be immutable, as intended, when SNP is enabled resulting in a potential limited loss of guest memory integrity.
CVE-2023-20526: Insufficient input validation in the ASP Bootloader may enable a privileged attacker with physical access to expose the contents of ASP memory potentially leading to a loss of confidentiality.
CVE-2021-26345: Failure to validate the value in APCB may allow an attacker with physical access to tamper with the APCB token to force an out-of-bounds memory read potentially resulting in a denial of service.
CVE-2023-20592: Issue with INVD instruction aka CacheWarpAttack (bsc#1215823).");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20200107~150100.3.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20200107~150100.3.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20200107~150100.3.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20200107~150100.3.40.1", rls:"SLES15.0SP2"))) {
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
