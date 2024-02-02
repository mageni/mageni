# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0348");
  script_cve_id("CVE-2023-34872");
  script_tag(name:"creation_date", value:"2023-12-18 04:13:00 +0000 (Mon, 18 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 18:43:26 +0000 (Fri, 04 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0348");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0348.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32600");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227884");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JQ3NYJ43U2MA7COKGMJDARZUAAOP45D4/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the MGASA-2023-0348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in Outline.cc for Poppler prior to 23.06.0 allows a
remote attacker to cause a Denial of Service (DoS) (crash) via a crafted
PDF file in OutlineItem::open. (CVE-2023-34872)
This update fixes that issue.");

  script_tag(name:"affected", value:"'poppler' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp-devel", rpm:"lib64poppler-cpp-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp0", rpm:"lib64poppler-cpp0~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-gir0.18", rpm:"lib64poppler-gir0.18~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib8", rpm:"lib64poppler-glib8~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5-devel", rpm:"lib64poppler-qt5-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5_1", rpm:"lib64poppler-qt5_1~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt6-devel", rpm:"lib64poppler-qt6-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt6_3", rpm:"lib64poppler-qt6_3~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler126", rpm:"lib64poppler126~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp-devel", rpm:"libpoppler-cpp-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-gir0.18", rpm:"libpoppler-gir0.18~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5_1", rpm:"libpoppler-qt5_1~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-devel", rpm:"libpoppler-qt6-devel~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6_3", rpm:"libpoppler-qt6_3~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126", rpm:"libpoppler126~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~23.02.0~1.1.mga9", rls:"MAGEIA9"))) {
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
