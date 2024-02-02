# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4727.1");
  script_cve_id("CVE-2022-1996");
  script_tag(name:"creation_date", value:"2023-12-13 04:29:36 +0000 (Wed, 13 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4727-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234727-1/");
  script_xref(name:"URL", value:"https://github.com/containerd/containerd/releases/tag/v1.7.8");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.1.10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'catatonit, containerd, runc' package(s) announced via the SUSE-SU-2023:4727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of runc and containerd fixes the following issues:
containerd:


Update to containerd v1.7.8. Upstream release notes:
 [link moved to references]

CVE-2022-1996: Fixed CORS bypass in go-restful (bsc#1200528)



catatonit:

Update to catatonit v0.2.0.

Change license to GPL-2.0-or-later.


Update to catatont v0.1.7


This release adds the ability for catatonit to be used as the only
 process in a pause container, by passing the -P flag (in this mode no
 subprocess is spawned and thus no signal forwarding is done).


Update to catatonit v0.1.6, which fixes a few bugs -- mainly ones related to
 socket activation or features somewhat adjacent to socket activation (such as
 passing file descriptors).


runc:

Update to runc v1.1.10. Upstream changelog is available from
 [link moved to references]");

  script_tag(name:"affected", value:"'catatonit, containerd, runc' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"catatonit", rpm:"catatonit~0.2.0~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catatonit-debuginfo", rpm:"catatonit-debuginfo~0.2.0~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catatonit-debugsource", rpm:"catatonit-debugsource~0.2.0~150000.3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.7.8~150000.103.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.7.8~150000.103.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.10~150000.55.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.10~150000.55.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"catatonit", rpm:"catatonit~0.2.0~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catatonit-debuginfo", rpm:"catatonit-debuginfo~0.2.0~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catatonit-debugsource", rpm:"catatonit-debugsource~0.2.0~150000.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.7.8~150000.103.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.7.8~150000.103.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.10~150000.55.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.10~150000.55.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.7.8~150000.103.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.7.8~150000.103.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.10~150000.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.10~150000.55.1", rls:"SLES15.0SP3"))) {
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
