# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0325.1");
  script_cve_id("CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20932", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"creation_date", value:"2024-02-06 07:13:39 +0000 (Tue, 06 Feb 2024)");
  script_version("2024-02-06T14:37:34+0000");
  script_tag(name:"last_modification", value:"2024-02-06 14:37:34 +0000 (Tue, 06 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:40 +0000 (Tue, 16 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0325-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240325-1/");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/jdk-updates-dev/2024-January/029089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openjdk' package(s) announced via the SUSE-SU-2024:0325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:
Updated to version 17.0.10 (January 2024 CPU):

CVE-2024-20918: Fixed an out of bounds access in the Hotspot JVM
 due to a missing bounds check (bsc#1218907).
CVE-2024-20919: Fixed a sandbox bypass in the Hotspot JVM class
 file verifier (bsc#1218903).
CVE-2024-20921: Fixed an incorrect optimization in the Hotspot JVM
 that could lead to corruption of JVM memory (bsc#1218905).
CVE-2024-20932: Fixed an incorrect handling of ZIP files with
 duplicate entries (bsc#1218908).
CVE-2024-20945: Fixed a potential private key leak through debug
 logs (bsc#1218909).
CVE-2024-20952: Fixed an RSA padding issue and timing side-channel
 attack against TLS (bsc#1218911).

Find the full release notes at:
[link moved to references]");

  script_tag(name:"affected", value:"'java-17-openjdk' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.10.0~150400.3.36.1", rls:"SLES15.0SP4"))) {
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
