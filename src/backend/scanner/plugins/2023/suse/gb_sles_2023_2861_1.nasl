# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2861.1");
  script_cve_id("CVE-2023-30581", "CVE-2023-30585", "CVE-2023-30588", "CVE-2023-30589", "CVE-2023-30590", "CVE-2023-31124", "CVE-2023-31130", "CVE-2023-31147", "CVE-2023-32067");
  script_tag(name:"creation_date", value:"2023-07-18 04:21:48 +0000 (Tue, 18 Jul 2023)");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:09:00 +0000 (Thu, 01 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2861-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2861-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232861-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs16' package(s) announced via the SUSE-SU-2023:2861-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs16 fixes the following issues:
Update to version 16.20.1:

CVE-2023-30581: Fixed mainModule.proto Bypass Experimental Policy Mechanism (bsc#1212574).
CVE-2023-30585: Fixed privilege escalation via Malicious Registry Key manipulation during Node.js installer repair process (bsc#1212579).
CVE-2023-30588: Fixed process interuption due to invalid Public Key information in x509 certificates (bsc#1212581).
CVE-2023-30589: Fixed HTTP Request Smuggling via empty headers separated by CR (bsc#1212582).
CVE-2023-30590: Fixed DiffieHellman key generation after setting a private key (bsc#1212583).
CVE-2023-31124: Fixed cross compilation issue with AutoTools that does not set CARES_RANDOM_FILE (bsc#1211607).
CVE-2023-31130: Fixed buffer underwrite problem in ares_inet_net_pton() (bsc#1211606).
CVE-2023-31147: Fixed insufficient randomness in generation of DNS query IDs (bsc#1211605).
CVE-2023-32067: Fixed denial-of-service via 0-byte UDP payload (bsc#1211604).

Bug fixes:

Increased the default timeout on unit tests from 2 to 20 minutes. This seems to have lead to build failures on some platforms, like s390x in Factory. (bsc#1211407)");

  script_tag(name:"affected", value:"'nodejs16' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs16", rpm:"nodejs16~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debuginfo", rpm:"nodejs16-debuginfo~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debugsource", rpm:"nodejs16-debugsource~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-devel", rpm:"nodejs16-devel~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-docs", rpm:"nodejs16-docs~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm16", rpm:"npm16~16.20.1~150300.7.24.2", rls:"SLES15.0SP3"))) {
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
