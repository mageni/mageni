# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0319");
  script_cve_id("CVE-2023-42795", "CVE-2023-45648");
  script_tag(name:"creation_date", value:"2023-11-16 04:12:21 +0000 (Thu, 16 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 15:43:48 +0000 (Mon, 16 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0319");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0319.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32377");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/9");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2023-0319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

Incomplete Cleanup vulnerability in Apache Tomcat.When recycling various
internal objects in Apache Tomcat from 11.0.0-M1 through 11.0.0-M11,
from 10.1.0-M1 through 10.1.13, from 9.0.0-M1 through 9.0.80 and from
8.5.0 through 8.5.93, an error could cause Tomcat to skip some parts of
the recycling process leading to information leaking from the current
request/response to the next. (CVE-2023-42795)

Improper Input Validation vulnerability in Apache Tomcat.Tomcat from
11.0.0-M1 through 11.0.0-M11, from 10.1.0-M1 through 10.1.13, from
9.0.0-M1 through 9.0.81 and from 8.5.0 through 8.5.93 did not correctly
parse HTTP trailer headers. A specially crafted, invalid trailer header
could cause Tomcat to treat a single request as multiple requests
leading to the possibility of request smuggling when behind a reverse
proxy. (CVE-2023-45648)");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.82~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.82~1.mga9", rls:"MAGEIA9"))) {
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
