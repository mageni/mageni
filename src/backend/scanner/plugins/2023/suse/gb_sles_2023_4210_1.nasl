# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4210.1");
  script_cve_id("CVE-2023-36478", "CVE-2023-36479", "CVE-2023-40167", "CVE-2023-41900", "CVE-2023-44487");
  script_tag(name:"creation_date", value:"2023-10-27 04:20:20 +0000 (Fri, 27 Oct 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4210-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234210-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jetty-minimal' package(s) announced via the SUSE-SU-2023:4210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jetty-minimal fixes the following issues:


Updated to version 9.4.53.v20231009:


CVE-2023-44487: Fixed a potential denial of service scenario via
 RST frame floods (bsc#1216169).

CVE-2023-36478: Fixed an integer overflow in the HTTP/2 HPACK
 decoder (bsc#1216162).
CVE-2023-40167: Fixed a permissive HTTP header parsing issue that
 could potentially lead to HTTP smuggling attacks (bsc#1215417).
CVE-2023-36479: Fixed an incorrect command execution when sending
 requests with certain characters in requested filenames
 (bsc#1215415).
CVE-2023-41900: Fixed an issue where an invalidated session would
 be allowed to perform a single request (bsc#1215416).");

  script_tag(name:"affected", value:"'jetty-minimal' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"jetty-http", rpm:"jetty-http~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-io", rpm:"jetty-io~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-security", rpm:"jetty-security~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-server", rpm:"jetty-server~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlet", rpm:"jetty-servlet~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util", rpm:"jetty-util~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util-ajax", rpm:"jetty-util-ajax~9.4.53~150200.3.22.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"jetty-http", rpm:"jetty-http~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-io", rpm:"jetty-io~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-security", rpm:"jetty-security~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-server", rpm:"jetty-server~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlet", rpm:"jetty-servlet~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util", rpm:"jetty-util~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util-ajax", rpm:"jetty-util-ajax~9.4.53~150200.3.22.1", rls:"SLES15.0SP3"))) {
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
