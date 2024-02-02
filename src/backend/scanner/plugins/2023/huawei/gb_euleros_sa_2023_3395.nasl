# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3395");
  script_cve_id("CVE-2023-27533", "CVE-2023-27534", "CVE-2023-27536");
  script_tag(name:"creation_date", value:"2023-12-14 04:31:45 +0000 (Thu, 14 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 16:23:46 +0000 (Fri, 07 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2023-3395)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3395");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3395");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2023-3395 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde (~) character to be wrongly replaced when used as a prefix in the first path element, in addition to its intended use as the first element to indicate a path relative to the user's home directory. Attackers can exploit this flaw to bypass filtering or execute arbitrary code by crafting a path like /~2/foo while accessing a server with a specific user.(CVE-2023-27534)

An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can reuse previously established connections with incorrect user permissions due to a failure to check for changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI transfers and could potentially result in unauthorized access to sensitive information. The safest option is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed.(CVE-2023-27536)

A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may allow an attacker to pass on maliciously crafted user name and 'telnet options' during server negotiation. The lack of proper input scrubbing allows an attacker to send content or perform option negotiation without the application's intent. This vulnerability could be exploited if an application allows user input, thereby enabling attackers to execute arbitrary code on the system.(CVE-2023-27533)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~46.h28.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~46.h28.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~46.h28.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
