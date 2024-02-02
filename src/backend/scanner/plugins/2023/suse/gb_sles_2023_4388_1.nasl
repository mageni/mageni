# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4388.1");
  script_cve_id("CVE-2023-34049");
  script_tag(name:"creation_date", value:"2023-11-10 04:25:47 +0000 (Fri, 10 Nov 2023)");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4388-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234388-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2023:4388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:
Security issues fixed:

CVE-2023-34049: arbitrary code execution via symlink attack (bsc#1215157)

Bugs fixed:

Fix optimization_order opt to prevent testsuite fails Improve salt.utils.json.find_json to avoid fails (bsc#1213293)
Use salt-call from salt bundle with transactional_update Only call native_str on curl_debug message in tornado when needed Implement the calling for batch async from the salt CLI Fix calculation of SLS context vars when trailing dots
 on targetted sls/state (bsc#1213518)
Rename salt-tests to python3-salt-testsuite Allow all primitive grain types for autosign_grains (bsc#1214477)");

  script_tag(name:"affected", value:"'salt' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson-debuginfo", rpm:"python-simplejson-debuginfo~3.17.2~150300.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson-debugsource", rpm:"python-simplejson-debugsource~3.17.2~150300.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-simplejson", rpm:"python3-simplejson~3.17.2~150300.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-simplejson-debuginfo", rpm:"python3-simplejson-debuginfo~3.17.2~150300.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-transactional-update", rpm:"salt-transactional-update~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150300.53.65.2", rls:"SLES15.0SP3"))) {
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
