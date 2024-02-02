# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0136.1");
  script_cve_id("CVE-2024-22365");
  script_tag(name:"creation_date", value:"2024-01-19 04:20:29 +0000 (Fri, 19 Jan 2024)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0136-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0136-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240136-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the SUSE-SU-2024:0136-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pam fixes the following issues:

CVE-2024-22365: Fixed a local denial of service during PAM login
 due to a missing check during path manipulation (bsc#1218475).
Check localtime_r() return value to fix crashing (bsc#1217000)");

  script_tag(name:"affected", value:"'pam' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Real Time 15-SP4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit-debuginfo", rpm:"pam-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debugsource", rpm:"pam-debugsource~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel-32bit", rpm:"pam-devel-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra", rpm:"pam-extra~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit", rpm:"pam-extra-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit-debuginfo", rpm:"pam-extra-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-debuginfo", rpm:"pam-extra-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit-debuginfo", rpm:"pam-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debugsource", rpm:"pam-debugsource~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel-32bit", rpm:"pam-devel-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra", rpm:"pam-extra~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit", rpm:"pam-extra-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit-debuginfo", rpm:"pam-extra-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-debuginfo", rpm:"pam-extra-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit-debuginfo", rpm:"pam-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debugsource", rpm:"pam-debugsource~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel-32bit", rpm:"pam-devel-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra", rpm:"pam-extra~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit", rpm:"pam-extra-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit-debuginfo", rpm:"pam-extra-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-debuginfo", rpm:"pam-extra-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit-debuginfo", rpm:"pam-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debugsource", rpm:"pam-debugsource~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel-32bit", rpm:"pam-devel-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra", rpm:"pam-extra~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit", rpm:"pam-extra-32bit~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit-debuginfo", rpm:"pam-extra-32bit-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-debuginfo", rpm:"pam-extra-debuginfo~1.3.0~150000.6.66.1", rls:"SLES15.0SP4"))) {
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
