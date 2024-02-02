# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4936.1");
  script_cve_id("CVE-2020-12912", "CVE-2020-8694", "CVE-2020-8695");
  script_tag(name:"creation_date", value:"2023-12-21 04:19:57 +0000 (Thu, 21 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:09:31 +0000 (Mon, 30 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4936-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234936-1/");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/24.0/#2407>");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/24.0/#2406");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/24.0/#2405");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker, rootlesskit' package(s) announced via the SUSE-SU-2023:4936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker, rootlesskit fixes the following issues:
docker:

Update to Docker 24.0.7-ce. See upstream changelong online at
 [link moved to references]. bsc#1217513

Deny containers access to /sys/devices/virtual/powercap by default.

CVE-2020-8694 bsc#1170415 CVE-2020-8695 bsc#1170446 CVE-2020-12912 bsc#1178760



Update to Docker 24.0.6-ce. See upstream changelong online at [link moved to references] . bsc#1215323


Add a docker.socket unit file, but with socket activation effectively
 disabled to ensure that Docker will always run even if you start the socket
 individually. Users should probably just ignore this unit file. bsc#1210141


Update to Docker 24.0.5-ce. See upstream changelong online at [link moved to references] . bsc#1213229


This update ships docker-rootless support in the docker-rootless-extra package. (jsc#PED-6180)
rootlesskit:

new package, for docker rootless support. (jsc#PED-6180)");

  script_tag(name:"affected", value:"'docker, rootlesskit' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~24.0.7_ce~150000.190.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~24.0.7_ce~150000.190.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~24.0.7_ce~150000.190.4", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~24.0.7_ce~150000.190.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~24.0.7_ce~150000.190.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~24.0.7_ce~150000.190.4", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~24.0.7_ce~150000.190.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~24.0.7_ce~150000.190.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~24.0.7_ce~150000.190.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~24.0.7_ce~150000.190.4", rls:"SLES15.0SP3"))) {
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
