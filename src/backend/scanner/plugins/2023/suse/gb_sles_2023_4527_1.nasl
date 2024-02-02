# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4527.1");
  script_cve_id("CVE-2023-46122");
  script_tag(name:"creation_date", value:"2023-11-23 04:30:31 +0000 (Thu, 23 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-31 14:52:24 +0000 (Tue, 31 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4527-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4527-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234527-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maven, maven-resolver, sbt, xmvn' package(s) announced via the SUSE-SU-2023:4527-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for maven, maven-resolver, sbt, xmvn fixes the following issues:

CVE-2023-46122: Fixed an arbitrary file write when extracting a
 crafted zip file with sbt (bsc#1216529).
Upgraded maven to version 3.9.4 Upgraded maven-resolver to version 1.9.15.");

  script_tag(name:"affected", value:"'maven, maven-resolver, sbt, xmvn' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Package Hub 15.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"SLES15.0SP3"))) {
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
