# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4986.1");
  script_cve_id("CVE-2023-5981");
  script_tag(name:"creation_date", value:"2023-12-29 04:20:32 +0000 (Fri, 29 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:40:21 +0000 (Mon, 04 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4986-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4986-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234986-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2023:4986-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

CVE-2023-5981: Fixed timing side-channel inside RSA-PSK key exchange (bsc#1217277).");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit-debuginfo", rpm:"libgnutls30-32bit-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-debuginfo", rpm:"libgnutls30-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28-debuginfo", rpm:"libgnutlsxx28-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel-32bit", rpm:"libgnutls-devel-32bit~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit-debuginfo", rpm:"libgnutls30-32bit-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-debuginfo", rpm:"libgnutls30-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28-debuginfo", rpm:"libgnutlsxx28-debuginfo~3.6.7~150200.14.28.1", rls:"SLES15.0SP3"))) {
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
