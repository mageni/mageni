# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4516.1");
  script_cve_id("CVE-2023-41913");
  script_tag(name:"creation_date", value:"2023-11-22 04:22:27 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 17:07:01 +0000 (Tue, 12 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4516-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4516-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234516-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2023:4516-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for strongswan fixes the following issues:

CVE-2023-41913: Fixed a bug in charon-tkm related to handling DH public values that can lead to remote code execution (bsc#1216901).");

  script_tag(name:"affected", value:"'strongswan' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.8.2~150000.4.23.2", rls:"SLES15.0SP1"))) {
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
