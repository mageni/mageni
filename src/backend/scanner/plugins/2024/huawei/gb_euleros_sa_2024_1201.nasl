# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1201");
  script_cve_id("CVE-2019-11707", "CVE-2019-9793", "CVE-2020-12417", "CVE-2022-38478", "CVE-2023-25735");
  script_tag(name:"creation_date", value:"2024-02-09 04:23:45 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 16:05:41 +0000 (Thu, 08 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for mozjs60 (EulerOS-SA-2024-1201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1201");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1201");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mozjs60' package(s) announced via the EulerOS-SA-2024-1201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A mechanism was discovered that removes some bounds checking for string, array, or typed array accesses if Spectre mitigations have been disabled. This vulnerability could allow an attacker to create an arbitrary value in compiled JavaScript, for which the range analysis will infer a fully controlled, incorrect range in circumstances where users have explicitly disabled Spectre mitigations. *Note: Spectre mitigations are currently enabled for all users by default settings.*. This vulnerability affects Thunderbird < 60.6, Firefox ESR < 60.6, and Firefox < 66.(CVE-2019-9793)

Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to be stored in the main compartment resulting in a use-after-free after unwrapping the proxy. This vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8.(CVE-2023-25735)

Members the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 103, Firefox ESR 102.1, and Firefox ESR 91.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Thunderbird < 102.2, Thunderbird < 91.13, Firefox ESR < 91.13, Firefox ESR < 102.2, and Firefox < 104.(CVE-2022-38478)

A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop. This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR < 60.7.1, Firefox < 67.0.3, and Thunderbird < 60.7.2.(CVE-2019-11707)

Due to confusion about ValueTags on JavaScript Objects, an object may pass through the type barrier, resulting in memory corruption and a potentially exploitable crash. *Note: this issue only affects Firefox on ARM64 platforms.* This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and Thunderbird < 68.10.0.(CVE-2020-12417)");

  script_tag(name:"affected", value:"'mozjs60' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"mozjs60", rpm:"mozjs60~60.2.2~4.h2.r9.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
