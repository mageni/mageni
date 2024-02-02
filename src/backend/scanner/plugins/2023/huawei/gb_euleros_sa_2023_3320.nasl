# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3320");
  script_cve_id("CVE-2023-4733", "CVE-2023-4734", "CVE-2023-4735", "CVE-2023-4738", "CVE-2023-4750", "CVE-2023-4751", "CVE-2023-4752", "CVE-2023-4781", "CVE-2023-5344", "CVE-2023-5441", "CVE-2023-5535");
  script_tag(name:"creation_date", value:"2023-12-12 04:35:10 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 14:16:54 +0000 (Mon, 16 Oct 2023)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-3320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3320");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3320");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-3320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free in GitHub repository vim/vim prior to v9.0.2010.(CVE-2023-5535)

NULL Pointer Dereference in GitHub repository vim/vim prior to 20d161ace307e28690229b68584f2d84556f8960.(CVE-2023-5441)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969.(CVE-2023-5344)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1873.(CVE-2023-4781)

Use After Free in GitHub repository vim/vim prior to 9.0.1858.(CVE-2023-4752)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1331.(CVE-2023-4751)

Use After Free in GitHub repository vim/vim prior to 9.0.1857.(CVE-2023-4750)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1848.(CVE-2023-4738)

Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1847.(CVE-2023-4735)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1846.(CVE-2023-4734)

Use After Free in GitHub repository vim/vim prior to 9.0.1840.(CVE-2023-4733)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0~1.h7.r10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0~1.h7.r10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.0~1.h7.r10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0~1.h7.r10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
