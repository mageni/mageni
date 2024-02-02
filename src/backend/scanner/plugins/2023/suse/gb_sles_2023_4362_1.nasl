# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4362.1");
  script_cve_id("CVE-2018-18454", "CVE-2018-18456", "CVE-2019-13287", "CVE-2019-14292", "CVE-2019-9545", "CVE-2019-9631", "CVE-2020-36023", "CVE-2022-37052", "CVE-2022-48545");
  script_tag(name:"creation_date", value:"2023-11-06 04:20:41 +0000 (Mon, 06 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 12:59:24 +0000 (Fri, 08 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4362-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234362-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2023:4362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

CVE-2019-9545: Fixed a potential crash due to uncontrolled recursion
 in the JBIG parser (bsc#1128114).
CVE-2019-9631: Fixed an out of bounds read when converting a PDF to
 an image (bsc#1129202).
CVE-2022-37052: Fixed a reachable assertion when extracting pages of
 a PDf file (bsc#1214726).
CVE-2020-36023: Fixed a stack bugger overflow in
 FoFiType1C:cvtGlyph (bsc#1214256).
CVE-2019-13287: Fixed an out-of-bounds read vulnerability in the
 function SplashXPath:strokeAdjust (bsc#1140745).
CVE-2018-18456: Fixed a stack-based buffer over-read via a crafted
 pdf file (bsc#1112428).
CVE-2018-18454: Fixed heap-based buffer over-read via a crafted pdf
 file (bsc#1112424).
CVE-2019-14292: Fixed an out of bounds read in GfxState.cc
 (bsc#1143570).
CVE-2022-48545: Fixed an infinite recursion in
 Catalog::findDestInTree which can cause denial of service
 (bsc#1214723).");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~16.40.1", rls:"SLES12.0SP5"))) {
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
