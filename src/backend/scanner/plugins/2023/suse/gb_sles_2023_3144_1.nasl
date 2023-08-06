# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3144.1");
  script_cve_id("CVE-2023-28370");
  script_tag(name:"creation_date", value:"2023-08-03 04:23:44 +0000 (Thu, 03 Aug 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:04:00 +0000 (Thu, 01 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3144-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233144-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2023:3144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:
python-tornado:

Security fixes:
CVE-2023-28370: Fixed an open redirect issue in the static file handler (bsc#1211741)

prometheus-blackbox_exporter:

Use obscpio for go modules service Set version number Set build date from SOURCE_DATE_EPOCH Update to 0.24.0 (bsc#1212279, jsc#PED-4556)
Requires go1.19 Avoid empty validation script Add rc symlink for backwards compatibility

spacecmd:

Version 4.3.22-1 Bypass traditional systems check on older SUMA instances (bsc#1208612)");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Client Tools for SLE 15, SUSE Manager Client Tools for SLE Micro 5, SUSE Manager Proxy 4.2, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-tornado", rpm:"python2-tornado~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-tornado-debuginfo", rpm:"python2-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-tornado", rpm:"python2-tornado~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-tornado-debuginfo", rpm:"python2-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"SLES15.0SP3"))) {
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
