# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4424.1");
  script_cve_id("CVE-2015-4645", "CVE-2015-4646", "CVE-2021-40153", "CVE-2021-41072");
  script_tag(name:"creation_date", value:"2023-11-14 04:25:56 +0000 (Tue, 14 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 18:39:50 +0000 (Fri, 24 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4424-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234424-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squashfs' package(s) announced via the SUSE-SU-2023:4424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squashfs fixes the following issues:

CVE-2015-4645,CVE-2015-4646: Multiple buffer overflows fixed in squashfs-tools (bsc#935380)
CVE-2021-40153: Fixed an issue where an attacker might have been
 able to write a file outside of destination (bsc#1189936)
CVE-2021-41072: Fixed an issue where an attacker might have been
 able to write a file outside the destination directory via a
 symlink (bsc#1190531).");

  script_tag(name:"affected", value:"'squashfs' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~8.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~8.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~8.3.2", rls:"SLES12.0SP5"))) {
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
