# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4521.1");
  script_cve_id("CVE-2023-5678");
  script_tag(name:"creation_date", value:"2023-11-22 04:22:27 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 16:54:10 +0000 (Tue, 21 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4521-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4521-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234521-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_1' package(s) announced via the SUSE-SU-2023:4521-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 fixes the following issues:

CVE-2023-5678: Fixed generating and checking of excessively long X9.42 DH keys that resulted in a possible Denial of Service (bsc#1216922).");

  script_tag(name:"affected", value:"'openssl-1_1' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo-32bit", rpm:"libopenssl1_1-debuginfo-32bit~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.1d~2.101.1", rls:"SLES12.0SP5"))) {
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
