# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2777.1");
  script_cve_id("CVE-2016-7069", "CVE-2017-7557", "CVE-2018-14663");
  script_tag(name:"creation_date", value:"2023-07-05 04:21:37 +0000 (Wed, 05 Jul 2023)");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2777-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232777-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsdist' package(s) announced via the SUSE-SU-2023:2777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsdist fixes the following issues:

Implements package 'dnsdist' with version 1.8.0 in SLE15. (jsc#PED-3402)
Downstream DNS resolver configuration should be chosen by the admin Security fix: fixes a possible record smugging with a crafted DNS query with trailing data (CVE-2018-14663, bsc#1114511)
Security fix: There is an issue that can lead to a denial of service on 32-bit if a backend sends crafted answers. (CVE-2016-7069, bsc#1054799)
Security fix: Alteration of dnsdist's ACL if the API is enabled, writable and an authenticated user is tricked into visiting a crafted website. (CVE-2017-7557, bsc#1054799)
SNMP support, exporting statistics and sending traps Preventing the packet cache from ageing responses when deployed in Various DNSCrypt-related fixes and improvements, including automatic key rotation");

  script_tag(name:"affected", value:"'dnsdist' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150100.3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150100.3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150100.3.5.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150100.3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150100.3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150100.3.5.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150100.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150100.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150100.3.5.1", rls:"SLES15.0SP3"))) {
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
