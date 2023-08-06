# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2971.1");
  script_cve_id("CVE-2023-24607", "CVE-2023-33285", "CVE-2023-34410", "CVE-2023-38197");
  script_tag(name:"creation_date", value:"2023-07-27 04:21:36 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-25 14:10:00 +0000 (Tue, 25 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2971-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2971-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232971-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2023:2971-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtbase fixes the following issues:

CVE-2023-24607: Fixed Qt SQL ODBC driver plugin DOS (bsc#1209616).
CVE-2023-33285: Fixed buffer overflow in QDnsLookup (bsc#1211642).
CVE-2023-34410: Fixed certificate validation does not always consider whether the root of a chain is a configured CA certificate (bsc#1211994).
CVE-2023-38197: Fixed infinite loops in QXmlStreamReader(bsc#1213326).");

  script_tag(name:"affected", value:"'libqt5-qtbase' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5", rpm:"libQt5Concurrent5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5-debuginfo", rpm:"libQt5Concurrent5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5", rpm:"libQt5Core5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5-debuginfo", rpm:"libQt5Core5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5", rpm:"libQt5DBus5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5-debuginfo", rpm:"libQt5DBus5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5", rpm:"libQt5Gui5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5-debuginfo", rpm:"libQt5Gui5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5", rpm:"libQt5Network5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5-debuginfo", rpm:"libQt5Network5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5", rpm:"libQt5OpenGL5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5-debuginfo", rpm:"libQt5OpenGL5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5", rpm:"libQt5PrintSupport5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5-debuginfo", rpm:"libQt5PrintSupport5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5", rpm:"libQt5Sql5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-debuginfo", rpm:"libQt5Sql5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-mysql", rpm:"libQt5Sql5-mysql~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-mysql-debuginfo", rpm:"libQt5Sql5-mysql-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-postgresql", rpm:"libQt5Sql5-postgresql~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-postgresql-debuginfo", rpm:"libQt5Sql5-postgresql-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite", rpm:"libQt5Sql5-sqlite~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite-debuginfo", rpm:"libQt5Sql5-sqlite-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-unixODBC", rpm:"libQt5Sql5-unixODBC~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-unixODBC-debuginfo", rpm:"libQt5Sql5-unixODBC-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5", rpm:"libQt5Test5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5-debuginfo", rpm:"libQt5Test5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5", rpm:"libQt5Widgets5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5-debuginfo", rpm:"libQt5Widgets5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5", rpm:"libQt5Xml5~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5-debuginfo", rpm:"libQt5Xml5-debuginfo~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-debugsource", rpm:"libqt5-qtbase-debugsource~5.6.2~6.36.1", rls:"SLES12.0SP5"))) {
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
