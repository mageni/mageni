# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3867.1");
  script_cve_id("CVE-2022-32149", "CVE-2022-41723", "CVE-2022-46146", "CVE-2023-29409");
  script_tag(name:"creation_date", value:"2023-09-29 04:23:57 +0000 (Fri, 29 Sep 2023)");
  script_version("2023-09-29T16:09:25+0000");
  script_tag(name:"last_modification", value:"2023-09-29 16:09:25 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:00 +0000 (Fri, 02 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3867-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233867-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2023:3867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:
golang-github-lusitaniae-apache_exporter:

Security issues fixed:
CVE-2022-32149: Fix denial of service vulnerability (bsc#1204501)
CVE-2022-41723: Fix uncontrolled resource consumption (bsc#1208270)
CVE-2022-46146: Fix authentication bypass vulnarability (bsc#1208046)
Changes and bugs fixed:
Updated to 1.0.0 (jsc#PED-5405)
Improved flag parsing Added support for custom headers


Changes from 0.13.1 Fix panic caused by missing flagConfig options


Added AppArmor profile Added sandboxing options to systemd service unit Build using promu Build with Go 1.19 Exclude s390 architecture

golang-github-prometheus-alertmanager:

CVE-2023-29409: Restrict RSA keys in certificates to less than or equal to 8192 bits to avoid DoSing client/server
 while validating signatures for extremely large RSA keys. (bsc#1213880)
 There are no direct source changes. The CVE is fixed rebuilding the sources with the patched Go version.

golang-github-prometheus-node_exporter:

CVE-2023-29409: Restrict RSA keys in certificates to less than or equal to 8192 bits to avoid DoSing client/server
 while validating signatures for extremely large RSA keys. (bsc#1213880)
 There are no direct source changes. The CVE is fixed rebuilding the sources with the patched Go version.

golang-github-prometheus-prometheus:

This update introduces breaking changes. Please, read carefully the provided informations.
Security issues fixed:
CVE-2022-41723: Fix uncontrolled resource consumption by updating Go to version 1.20.1 (bsc#1208298)
Updated to 2.45.0 (jsc#PED-5406):
[FEATURE] API: New limit parameter to limit the number of items returned by /api/v1/status/tsdb endpoint
[FEATURE] Config: Add limits to global config
[FEATURE] Consul SD: Added support for path_prefix
[FEATURE] Native histograms: Add option to scrape both classic and native histograms.
[FEATURE] Native histograms: Added support for two more arithmetic operators avg_over_time and sum_over_time
[FEATURE] Promtool: When providing the block id, only one block will be loaded and analyzed
[FEATURE] Remote-write: New Azure ad configuration to support remote writing directly to Azure Monitor workspace
[FEATURE] TSDB: Samples per chunk are now configurable with flag storage.tsdb.samples-per-chunk. By default set
 to its former value 120
[ENHANCEMENT] Native histograms: bucket size can now be limited to avoid scrape fails
[ENHANCEMENT] TSDB: Dropped series are now deleted from the WAL sooner
[BUGFIX] Native histograms: ChunkSeries iterator now checks if a new sample can be appended to the open chunk
[BUGFIX] Native histograms: Fix Histogram Appender Appendable() segfault
[BUGFIX] Native histograms: Fix setting reset header to gauge histograms in seriesToChunkEncoder
[BUGFIX] TSDB: Tombstone intervals are not modified after Get() call
[BUGFIX] TSDB: Use path/filepath to set the WAL directory.
Changes from 2.44.0:
[FEATURE] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Manager Client Tools for SLE 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.5.0~1.27.2", rls:"SLES12.0SP5"))) {
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
