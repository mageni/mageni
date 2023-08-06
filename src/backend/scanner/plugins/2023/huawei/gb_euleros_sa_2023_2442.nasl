# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2442");
  script_cve_id("CVE-2022-1725", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2287", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2345", "CVE-2022-2845", "CVE-2022-2980", "CVE-2022-3234", "CVE-2022-3256", "CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352", "CVE-2022-3520", "CVE-2022-3705", "CVE-2022-4141", "CVE-2022-4292", "CVE-2023-0049", "CVE-2023-0433", "CVE-2023-1175");
  script_tag(name:"creation_date", value:"2023-07-25 08:38:57 +0000 (Tue, 25 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 12:26:00 +0000 (Tue, 06 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-2442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2442");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2442");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-2442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect Calculation of Buffer Size in GitHub repository vim/vim prior to 9.0.1378.(CVE-2023-1175)

Use After Free in GitHub repository vim/vim prior to 9.0.0882.(CVE-2022-4292)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225.(CVE-2023-0433)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.(CVE-2023-0049)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0765.(CVE-2022-3520)

Heap based buffer overflow in vim/vim 9.0.0946 and below by allowing an attacker to CTRL-W gf in the expression used in the RHS of the substitute command.(CVE-2022-4141)

Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218.(CVE-2022-2845)

Use After Free in GitHub repository vim/vim prior to 9.0.(CVE-2022-2289)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2304)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.(CVE-2022-2285)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2284)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2287)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2206)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2210)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.(CVE-2022-2208)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2207)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2183)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2125)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2124)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2126)

Use After Free in GitHub repository vim/vim prior to 9.0.0046.(CVE-2022-2345)


Use After Free in GitHub repository vim/vim prior to 9.0.0614.(CVE-2022-3352)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4959.(CVE-2022-1725)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483.(CVE-2022-3234)

A vulnerability was found in vim and classified as problematic. Affected by this issue is the function qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-212324.(CVE-2022-3705)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598.(CVE-2022-3324)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577.(CVE-2022-3296)

Use After Free in GitHub repository vim/vim prior to 9.0.0579.(CVE-2022-3297)

NULL Pointer Dereference in GitHub repository vim/vim ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.4.160~4.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~4.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~4.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~4.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~4.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
