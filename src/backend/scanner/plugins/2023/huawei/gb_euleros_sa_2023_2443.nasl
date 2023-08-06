# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2443");
  script_cve_id("CVE-2019-14558", "CVE-2019-14586", "CVE-2019-14587", "CVE-2021-28210", "CVE-2021-38578");
  script_tag(name:"creation_date", value:"2023-07-25 08:38:57 +0000 (Tue, 25 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 02:12:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for edk2 (EulerOS-SA-2023-2443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2443");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2443");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'edk2' package(s) announced via the EulerOS-SA-2023-2443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient control flow management in BIOS firmware for 8th, 9th, 10th Generation Intel(R) Core(TM), Intel(R) Celeron(R) Processor 4000 & 5000 Series Processors may allow an authenticated user to potentially enable denial of service via adjacent access(CVE-2019-14558)

Use after free vulnerability in EDK II may allow an authenticated user to potentially enable escalation of privilege, information disclosure and/or denial of service via adjacent access.(CVE-2019-14586)

Logic issue EDK II may allow an unauthenticated user to potentially enable denial of service via adjacent access.(CVE-2019-14587)

An unlimited recursion in DxeCore in EDK II.(CVE-2021-28210)

Existing CommBuffer checks in SmmEntryPoint will not catch underflow when computing BufferSize.(CVE-2021-38578)");

  script_tag(name:"affected", value:"'edk2' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"edk", rpm:"edk~2.0~30.110", rls:"EULEROSVIRT-3.0.6.6"))) {
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
