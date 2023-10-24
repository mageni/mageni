# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0290");
  script_cve_id("CVE-2023-43115");
  script_tag(name:"creation_date", value:"2023-10-20 04:12:17 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-21 16:27:00 +0000 (Thu, 21 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0290");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0290.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32400");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PG5AQV7JOL5TAU76FWPJCMSKO5DREKV5/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6433-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the MGASA-2023-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:

In Artifex Ghostscript through 10.01.2, gdevijs.c in GhostPDL can lead
to remote code execution via crafted PostScript documents because they
can switch to the IJS device, or change the IjsServer parameter, after
SAFER has been activated. (CVE-2023-43115)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~162.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~162.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.53.3~2.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~162.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~162.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs10", rpm:"lib64gs10~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~173.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~173.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs10", rpm:"libgs10~10.00.0~6.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~173.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~173.3.mga9", rls:"MAGEIA9"))) {
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
