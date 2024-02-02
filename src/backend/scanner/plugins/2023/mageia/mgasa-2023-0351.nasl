# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0351");
  script_cve_id("CVE-2023-46751");
  script_tag(name:"creation_date", value:"2023-12-19 04:12:31 +0000 (Tue, 19 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-09 04:52:20 +0000 (Sat, 09 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0351)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0351");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0351.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32619");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6551-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the MGASA-2023-0351 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability.
An issue was discovered in the function gdev_prn_open_printer_seekable()
in Artifex Ghostscript through 10.02.0 allows remote attackers to crash
the application via a dangling pointer. (CVE-2023-46751)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs10", rpm:"lib64gs10~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~173.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~173.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs10", rpm:"libgs10~10.00.0~6.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~173.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~173.4.mga9", rls:"MAGEIA9"))) {
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
