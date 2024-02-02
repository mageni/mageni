# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4152.1");
  script_cve_id("CVE-2023-22081");
  script_tag(name:"creation_date", value:"2023-10-23 04:21:26 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 22:15:13 +0000 (Tue, 17 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4152-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234152-1/");
  script_xref(name:"URL", value:"https://www.oracle.com/java/technologies/javase/11all-relnotes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2023:4152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:


Upgraded to JDK 11.0.21+9 (October 2023 CPU):


CVE-2023-22081: Fixed a partial denial of service issue that
 could be triggered via HTTPS (bsc#1216374).


Please visit the Oracle Release Notes page for the full changelog:
[link moved to references]");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.21.0~3.69.1", rls:"SLES12.0SP5"))) {
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
