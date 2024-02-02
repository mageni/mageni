# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3120");
  script_cve_id("CVE-2023-24805");
  script_tag(name:"creation_date", value:"2023-11-09 04:28:52 +0000 (Thu, 09 Nov 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 17:05:06 +0000 (Thu, 25 May 2023)");

  script_name("Huawei EulerOS: Security Advisory for cups-filters (EulerOS-SA-2023-3120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3120");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3120");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'cups-filters' package(s) announced via the EulerOS-SA-2023-3120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cups-filters contains backends, filters, and other software required to get the cups printing service working on operating systems other than macos. If you use the Backend Error Handler (beh) to create an accessible network printer, this security vulnerability can cause remote code execution. `beh.c` contains the line `retval = system(cmdline) >> 8,` which calls the `system` command with the operand `cmdline`. `cmdline` contains multiple user controlled, unsanitized values. As a result an attacker with network access to the hosted print server can exploit this vulnerability to inject system commands which are executed in the context of the running server. This issue has been addressed in commit `8f2740357` and is expected to be bundled in the next release. Users are advised to upgrade when possible and to restrict access to network printers in the meantime.(CVE-2023-24805)");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.20.3~9.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filters-libs", rpm:"cups-filters-libs~1.20.3~9.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
