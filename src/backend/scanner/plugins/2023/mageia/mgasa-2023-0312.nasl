# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0312");
  script_cve_id("CVE-2023-45853");
  script_tag(name:"creation_date", value:"2023-11-10 04:12:04 +0000 (Fri, 10 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 12:44:29 +0000 (Thu, 19 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0312)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0312");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0312.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32426");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/20/9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib' package(s) announced via the MGASA-2023-0312 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:

MiniZip in zlib through 1.3 has an integer overflow and resultant
heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long
filename, comment, or extra field. (CVE-2023-45853)");

  script_tag(name:"affected", value:"'zlib' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip-devel", rpm:"lib64minizip-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip1", rpm:"lib64minizip1~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-devel", rpm:"lib64zlib-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-static-devel", rpm:"lib64zlib-static-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib1", rpm:"lib64zlib1~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip-devel", rpm:"libminizip-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-devel", rpm:"libzlib-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-static-devel", rpm:"libzlib-static-devel~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib1", rpm:"libzlib1~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib", rpm:"zlib~1.2.12~1.4.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip-devel", rpm:"lib64minizip-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip1", rpm:"lib64minizip1~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-devel", rpm:"lib64zlib-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-static-devel", rpm:"lib64zlib-static-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib1", rpm:"lib64zlib1~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip-devel", rpm:"libminizip-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-devel", rpm:"libzlib-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-static-devel", rpm:"libzlib-static-devel~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib1", rpm:"libzlib1~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib", rpm:"zlib~1.2.13~1.1.mga9", rls:"MAGEIA9"))) {
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
