# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0315");
  script_cve_id("CVE-2023-46846", "CVE-2023-46847", "CVE-2023-46848");
  script_tag(name:"creation_date", value:"2023-11-10 04:12:04 +0000 (Fri, 10 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 20:03:23 +0000 (Mon, 13 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0315");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0315.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32486");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-j83v-w3p4-5cqh");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-phqj-m8gv-cq4g");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-2g3c-pg7q-g59w");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2023-0315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

Request/Response smuggling in HTTP/1.1 and ICAP. (CVE-2023-46846)

Denial of Service in HTTP Digest Authentication. (CVE-2023-46847)

Denial of Service in FTP. (CVE-2023-46848)");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~5.9~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~5.9~1.1.mga9", rls:"MAGEIA9"))) {
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
