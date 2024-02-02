# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0012.1");
  script_cve_id("CVE-2023-51764");
  script_tag(name:"creation_date", value:"2024-01-03 04:20:17 +0000 (Wed, 03 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:19:53 +0000 (Fri, 05 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0012-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240012-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix' package(s) announced via the SUSE-SU-2024:0012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postfix fixes the following issues:

CVE-2023-51764: Fixed SMTP smuggling attack (bsc#1218304).");

  script_tag(name:"affected", value:"'postfix' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Real Time 15-SP4, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"SLES15.0SP4"))) {
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
