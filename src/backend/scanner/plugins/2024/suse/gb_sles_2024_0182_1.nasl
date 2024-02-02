# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0182.1");
  script_cve_id("CVE-2023-50229", "CVE-2023-50230");
  script_tag(name:"creation_date", value:"2024-01-24 04:20:59 +0000 (Wed, 24 Jan 2024)");
  script_version("2024-01-24T05:06:24+0000");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0182-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240182-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the SUSE-SU-2024:0182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bluez fixes the following issues:

CVE-2023-50229: Fixed an out of bounds write in the primary version
 counter for the Phone Book Access Profile implementation
 (bsc#1218300).
CVE-2023-50230: Fixed an out of bounds write in the secondary
 version counter for the Phone Book Access Profile implementation
 (bsc#1218301).");

  script_tag(name:"affected", value:"'bluez' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated", rpm:"bluez-deprecated~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated-debuginfo", rpm:"bluez-deprecated-debuginfo~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-devel", rpm:"bluez-devel~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3-debuginfo", rpm:"libbluetooth3-debuginfo~5.55~150300.3.28.1", rls:"SLES15.0SP3"))) {
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
