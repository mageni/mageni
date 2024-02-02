# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0166.1");
  script_cve_id("CVE-2021-41229", "CVE-2023-50229", "CVE-2023-50230");
  script_tag(name:"creation_date", value:"2024-01-22 04:20:38 +0000 (Mon, 22 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 01:30:32 +0000 (Wed, 17 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0166-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240166-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the SUSE-SU-2024:0166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bluez fixes the following issues:

CVE-2021-41229: Fix leaking buffers stored in cstates cache
 (bsc#1192760).
CVE-2023-50229: Fixed an out of bounds write in the primary version
 counter for the Phone Book Access Profile implementation
 (bsc#1218300).
CVE-2023-50230: Fixed an out of bounds write in the secondary
 version counter for the Phone Book Access Profile implementation
 (bsc#1218301).");

  script_tag(name:"affected", value:"'bluez' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-devel", rpm:"bluez-devel~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3-debuginfo", rpm:"libbluetooth3-debuginfo~5.48~150000.5.54.1", rls:"SLES15.0SP1"))) {
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
