# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0264");
  script_cve_id("CVE-2023-32002", "CVE-2023-32006", "CVE-2023-32559");
  script_tag(name:"creation_date", value:"2023-09-25 04:14:33 +0000 (Mon, 25 Sep 2023)");
  script_version("2023-10-04T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-10-04 05:06:18 +0000 (Wed, 04 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-24 21:09:00 +0000 (Thu, 24 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0264");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0264.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32176");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28809");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.17.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.17.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs, yarnpkg' package(s) announced via the MGASA-2023-0264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security release. As well, it fixes v8 headers detection
(mga#28809)

The following CVEs are fixed in this release:
 CVE-2023-32002: Policies can be bypassed via Module._load (High)
 CVE-2023-32006: Policies can be bypassed by
 module.constructor.createRequire (Medium)
 CVE-2023-32559: Policies can be bypassed via process.binding (Medium)
 OpenSSL Security Releases
 OpenSSL security advisory 14th July.
 OpenSSL security advisory 19th July.
 OpenSSL security advisory 31st July

More detailed information on each of the vulnerabilities can be found in
August 2023 Security Releases blog post.");

  script_tag(name:"affected", value:"'nodejs, yarnpkg' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~18.17.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~18.17.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~18.17.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~18.17.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~9.6.7~1.18.17.1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~10.2.154.26.mga8~3.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~18.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~18.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~18.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~18.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~9.6.7~1.18.17.1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~10.2.154.26.mga9~3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.19~13.mga9", rls:"MAGEIA9"))) {
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
