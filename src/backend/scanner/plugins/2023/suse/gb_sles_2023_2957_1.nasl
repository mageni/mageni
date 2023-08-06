# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2957.1");
  script_cve_id("CVE-2007-4559", "CVE-2023-24329");
  script_tag(name:"creation_date", value:"2023-07-26 04:25:46 +0000 (Wed, 26 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 19:28:00 +0000 (Mon, 27 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2957-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2957-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232957-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2023:2957-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:
Update to 3.9.17:

urllib.parse.urlsplit() now strips leading C0 control and space
 characters following the specification for URLs defined by WHATWG in
 response to CVE-2023-24329 (bsc#1208471).
Fixed a security in flaw in uu.decode() that could allow for directory
 traversal based on the input if no out_file was specified.
Do not expose the local on-disk location in directory indexes produced by
 http.client.SimpleHTTPRequestHandler.
trace.main now uses io.open_code() for files
 to be executed instead of raw open().
CVE-2007-4559: The extraction methods in tarfile, and shutil.unpack_archive(), have
 a new filter argument that allows limiting tar features than may be
 surprising or dangerous, such as creating files outside the destination
 directory. See Extraction filters for details (fixing bsc#1203750).
Fixed a deadlock at shutdown when clearing thread states if any
 finalizer tries to acquire the runtime head lock.
Fixed a crash due to a race while iterating over thread states in
 clearing threading.local.");

  script_tag(name:"affected", value:"'python39' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.17~150300.4.30.1", rls:"SLES15.0SP3"))) {
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
