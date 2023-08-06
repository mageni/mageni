# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2991.1");
  script_cve_id("CVE-2022-47015");
  script_tag(name:"creation_date", value:"2023-07-27 04:21:36 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 19:24:00 +0000 (Thu, 23 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2991-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232991-1/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-21-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-21-changelog/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2023:2991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:
This update provides MariaDB 10.5.21.
See release notes at [link moved to references]
and changelog at [link moved to references] .
Security issues fixed:

CVE-2022-47015: Fixed a NULL pointer dereference in spider_db_mbase:print_warnings (bsc#1207404).");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd-devel", rpm:"libmariadbd-devel~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19-debuginfo", rpm:"libmariadbd19-debuginfo~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.5.21~150300.3.32.5", rls:"SLES15.0SP3"))) {
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
