# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4622.1");
  script_cve_id("CVE-2021-45930", "CVE-2023-32573", "CVE-2023-32763", "CVE-2023-34410", "CVE-2023-37369", "CVE-2023-38197");
  script_tag(name:"creation_date", value:"2023-12-01 04:31:51 +0000 (Fri, 01 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-25 14:10:05 +0000 (Tue, 25 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4622-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4622-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234622-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt4' package(s) announced via the SUSE-SU-2023:4622-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt4 fixes the following issues:

CVE-2021-45930: Fix out of-bounds write when parsing path nodes (bsc#1196654).
CVE-2023-32573: Fix missing initialization of QSvgFont unitsPerEm (bsc#1211298).
CVE-2023-32763: Fix potential buffer when rendering a SVG file with an image inside (bsc#1211798).
CVE-2023-34410: Fix missing sync of disablement of loading root certificates in qsslsocketprivate (bsc#1211994).
CVE-2023-37369: Fix buffer overflow in QXmlStreamReader (bsc#1214327).
CVE-2023-38197: Fix infinite loops in QXmlStreamReader (bsc#1213326).");

  script_tag(name:"affected", value:"'libqt4' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debuginfo-32bit", rpm:"libqt4-debuginfo-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debuginfo", rpm:"libqt4-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debugsource", rpm:"libqt4-debugsource~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debuginfo", rpm:"libqt4-devel-doc-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debugsource", rpm:"libqt4-devel-doc-debugsource~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-debuginfo-32bit", rpm:"libqt4-qt3support-debuginfo-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-debuginfo", rpm:"libqt4-qt3support-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-debuginfo-32bit", rpm:"libqt4-sql-debuginfo-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-debuginfo", rpm:"libqt4-sql-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-mysql", rpm:"libqt4-sql-mysql~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-mysql-debuginfo", rpm:"libqt4-sql-mysql-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-plugins-debugsource", rpm:"libqt4-sql-plugins-debugsource~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-debuginfo", rpm:"libqt4-sql-sqlite-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-debuginfo-32bit", rpm:"libqt4-x11-debuginfo-32bit~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-debuginfo", rpm:"libqt4-x11-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools", rpm:"qt4-x11-tools~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools-debuginfo", rpm:"qt4-x11-tools-debuginfo~4.8.7~8.19.1", rls:"SLES12.0SP5"))) {
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
