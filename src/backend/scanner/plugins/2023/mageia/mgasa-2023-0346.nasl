# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0346");
  script_cve_id("CVE-2023-44441", "CVE-2023-44442", "CVE-2023-44443", "CVE-2023-44444");
  script_tag(name:"creation_date", value:"2023-12-18 04:13:00 +0000 (Mon, 18 Dec 2023)");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2023-0346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0346");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0346.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32548");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/20/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gegl, gimp' package(s) announced via the MGASA-2023-0346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GIMP has been updated to version 2.10.36 to fix several security issues.
CVE-2023-44441: GIMP DDS File Parsing Heap-based Buffer Overflow Remote
Code Execution Vulnerability
CVE-2023-44442: GIMP PSD File Parsing Heap-based Buffer Overflow Remote
Code Execution Vulnerability
CVE-2023-44443: GIMP PSP File Parsing Integer Overflow Remote Code
Execution Vulnerability
CVE-2023-44444: GIMP PSP File Parsing Off-By-One Remote Code Execution
Vulnerability");

  script_tag(name:"affected", value:"'gegl, gimp' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gegl", rpm:"gegl~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.10.36~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gegl-devel", rpm:"lib64gegl-devel~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gegl-gir0.4", rpm:"lib64gegl-gir0.4~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gegl0.4_0", rpm:"lib64gegl0.4_0~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.10.36~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.10.36~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgegl-devel", rpm:"libgegl-devel~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgegl-gir0.4", rpm:"libgegl-gir0.4~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgegl0.4_0", rpm:"libgegl0.4_0~0.4.38~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.10.36~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.10.36~1.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.10.36~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.10.36~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.10.36~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.10.36~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.10.36~1.mga9", rls:"MAGEIA9"))) {
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
