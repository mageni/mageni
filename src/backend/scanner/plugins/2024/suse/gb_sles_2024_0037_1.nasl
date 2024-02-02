# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0037.1");
  script_cve_id("CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");
  script_tag(name:"creation_date", value:"2024-01-08 04:20:21 +0000 (Mon, 08 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 17:12:08 +0000 (Thu, 01 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0037-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240037-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxkbcommon' package(s) announced via the SUSE-SU-2024:0037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxkbcommon fixes the following issues:
Fixed multiple memory handling and correctness issues (bsc#1105832):

CVE-2018-15859 CVE-2018-15856 CVE-2018-15858 CVE-2018-15864 CVE-2018-15863 CVE-2018-15862 CVE-2018-15861 CVE-2018-15855 CVE-2018-15854 CVE-2018-15857 CVE-2018-15853");

  script_tag(name:"affected", value:"'libxkbcommon' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-debugsource", rpm:"libxkbcommon-debugsource~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0", rpm:"libxkbcommon-x11-0~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0-32bit", rpm:"libxkbcommon-x11-0-32bit~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0-debuginfo", rpm:"libxkbcommon-x11-0-debuginfo~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0-debuginfo-32bit", rpm:"libxkbcommon-x11-0-debuginfo-32bit~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0", rpm:"libxkbcommon0~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0-32bit", rpm:"libxkbcommon0-32bit~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0-debuginfo", rpm:"libxkbcommon0-debuginfo~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0-debuginfo-32bit", rpm:"libxkbcommon0-debuginfo-32bit~0.6.1~9.3.1", rls:"SLES12.0SP5"))) {
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
