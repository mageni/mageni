# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2571.1");
  script_tag(name:"creation_date", value:"2023-06-22 04:21:16 +0000 (Thu, 22 Jun 2023)");
  script_version("2023-06-22T10:34:14+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:14 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2571-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2571-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232571-1/");
  script_xref(name:"URL", value:"https://docs.saltproject.io/en/latest/topics/releases/3006.0.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Salt' package(s) announced via the SUSE-SU-2023:2571-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:
salt:

Update to Salt release version 3006.0 (jsc#PED-4361)
See release notes: [link moved to references] Add missing patch after rebase to fix collections Mapping issues Add python3-looseversion as new dependency for salt Add python3-packaging as new dependency for salt Allow entrypoint compatibility for 'importlib-metadata>=5.0.0' (bsc#1207071)
Avoid conflicts with Salt dependencies versions (bsc#1211612)
Avoid failures due transactional_update module not available in Salt 3006.0 (bsc#1211754)
Create new salt-tests subpackage containing Salt tests Drop conflictive patch dicarded from upstream Fix package build with old setuptools versions Fix SLS rendering error when Jinja macros are used Fix version detection and avoid building and testing failures Prevent deadlocks in salt-ssh executions Require python3-jmespath runtime dependency (bsc#1209233)
Make master_tops compatible with Salt 3000 and older minions (bsc#1212516, bsc#1212517)

python-jmespath:

Deliver python3-jmespath to SUSE Linux Enterprise Micro on s390x architecture as it is now required by Salt
 (no source changes)

python-ply:

Deliver python3-ply to SUSE Linux Enterprise Micro on s390x architecture as it is a requirement for python-jmespath
 (no source changes)");

  script_tag(name:"affected", value:"'Salt' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2, SUSE Package Hub 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"python2-ply", rpm:"python2-ply~3.10~150000.3.3.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jmespath", rpm:"python3-jmespath~0.9.3~150000.3.3.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ply", rpm:"python3-ply~3.10~150000.3.3.4", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python2-ply", rpm:"python2-ply~3.10~150000.3.3.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jmespath", rpm:"python3-jmespath~0.9.3~150000.3.3.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ply", rpm:"python3-ply~3.10~150000.3.3.4", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson-debuginfo", rpm:"python-simplejson-debuginfo~3.17.2~150300.3.2.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson-debugsource", rpm:"python-simplejson-debugsource~3.17.2~150300.3.2.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jmespath", rpm:"python3-jmespath~0.9.3~150000.3.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ply", rpm:"python3-ply~3.10~150000.3.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-simplejson", rpm:"python3-simplejson~3.17.2~150300.3.2.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-simplejson-debuginfo", rpm:"python3-simplejson-debuginfo~3.17.2~150300.3.2.3", rls:"SLES15.0SP3"))) {
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
