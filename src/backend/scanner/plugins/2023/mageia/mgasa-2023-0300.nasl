# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0300");
  script_cve_id("CVE-2023-43641");
  script_tag(name:"creation_date", value:"2023-10-24 04:12:00 +0000 (Tue, 24 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 17:53:23 +0000 (Fri, 27 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0300");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0300.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32372");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/09/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcue' package(s) announced via the MGASA-2023-0300 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Versions 2.2.1 and prior are vulnerable to out-of-bounds array access.
A user of the GNOME desktop environment can be exploited by downloading
a cue sheet from a malicious webpage. Because the file is saved to
`~/Downloads`, it is then automatically scanned by tracker-miners. And
because it has a .cue filename extension, tracker-miners use libcue to
parse the file. The file exploits the vulnerability in libcue to gain
code execution. (CVE-2023-43641)");

  script_tag(name:"affected", value:"'libcue' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64cue-devel", rpm:"lib64cue-devel~2.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cue2", rpm:"lib64cue2~2.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue", rpm:"libcue~2.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue-devel", rpm:"libcue-devel~2.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue2", rpm:"libcue2~2.3.0~1.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64cue-devel", rpm:"lib64cue-devel~2.3.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cue2", rpm:"lib64cue2~2.3.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue", rpm:"libcue~2.3.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue-devel", rpm:"libcue-devel~2.3.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcue2", rpm:"libcue2~2.3.0~1.mga9", rls:"MAGEIA9"))) {
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
