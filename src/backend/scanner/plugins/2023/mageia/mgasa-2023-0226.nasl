# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0226");
  script_cve_id("CVE-2023-30581", "CVE-2023-30582", "CVE-2023-30583", "CVE-2023-30584", "CVE-2023-30585", "CVE-2023-30586", "CVE-2023-30587", "CVE-2023-30588", "CVE-2023-30589", "CVE-2023-30590");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 17:21:00 +0000 (Tue, 11 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0226");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0226.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32047");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.16.1");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2023-security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2023-0226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Current nodejs 14 branch in Mageia 8 is end of life and there are no more
security updates.

This release allows to move to the new nodejs 18 LTS branch and fixes the
following CVEs
CVE-2023-30581: mainModule.__proto__ Bypass Experimental Policy Mechanism
(High)
CVE-2023-30585: Privilege escalation via Malicious Registry Key
manipulation during Node.js installer repair process (Medium)
CVE-2023-30588: Process interuption due to invalid Public Key information
in x509 certificates (Medium)
CVE-2023-30589: HTTP Request Smuggling via Empty headers separated by CR
(Medium)
CVE-2023-30590: DiffieHellman does not generate keys after setting a
private key (Medium)
OpenSSL Security Releases
 OpenSSL security advisory 28th March.
 OpenSSL security advisory 20th April.
 OpenSSL security advisory 30th May
c-ares vulnerabilities:
 GHSA-9g78-jv2r-p7vc
 GHSA-8r8p-23f3-64c2
 GHSA-54xr-f67r-4pc4
 GHSA-x6mf-cxr9-8q6v");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~18.16.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~18.16.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~18.16.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~18.16.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~9.5.1~1.18.16.1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~10.2.154.26.mga8~2.mga8", rls:"MAGEIA8"))) {
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
