# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0299");
  script_cve_id("CVE-2023-38552", "CVE-2023-39333", "CVE-2023-44487", "CVE-2023-45143");
  script_tag(name:"creation_date", value:"2023-10-23 04:11:50 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0299");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0299.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32403");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.18.2");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.18.1");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/october-2023-security-releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs, yarnpkg' package(s) announced via the MGASA-2023-0299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security release. The following CVEs are fixed in this
release:

CVE-2023-44487: nghttp2 Security Release (High)
CVE-2023-45143: undici Security Release (High)
CVE-2023-38552: Integrity checks according to policies can be
circumvented (Medium)
CVE-2023-39333: Code injection via WebAssembly export names (Low)

More detailed information on each of the vulnerabilities can be found in
October 2023 Security Releases blog post.");

  script_tag(name:"affected", value:"'nodejs, yarnpkg' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~18.18.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~18.18.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~18.18.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~18.18.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~9.8.1~1.18.18.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~10.2.154.26.mga9~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.19~14.mga9", rls:"MAGEIA9"))) {
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
