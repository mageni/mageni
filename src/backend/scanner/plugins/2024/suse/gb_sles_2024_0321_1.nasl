# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0321.1");
  script_cve_id("CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20926", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"creation_date", value:"2024-02-05 04:20:14 +0000 (Mon, 05 Feb 2024)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:42 +0000 (Tue, 16 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0321-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240321-1/");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/jdk-updates-dev/2024-January/029215.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2024:0321-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:
Updated to version 11.0.22 (January 2024 CPU):

CVE-2024-20918: Fixed an out of bounds access in the Hotspot JVM
 due to a missing bounds check (bsc#1218907).
CVE-2024-20919: Fixed a sandbox bypass in the Hotspot JVM class
 file verifier (bsc#1218903).
CVE-2024-20921: Fixed an incorrect optimization in the Hotspot JVM
 that could lead to corruption of JVM memory (bsc#1218905).
CVE-2024-20926: Fixed arbitrary Java code execution in Nashorn (bsc#1218906).
CVE-2024-20945: Fixed a potential private key leak through debug
 logs (bsc#1218909).
CVE-2024-20952: Fixed an RSA padding issue and timing side-channel
 attack against TLS (bsc#1218911).

Find the full release notes at:
[link moved to references]");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3, SUSE Package Hub 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.22.0~150000.3.110.1", rls:"SLES15.0SP4"))) {
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
