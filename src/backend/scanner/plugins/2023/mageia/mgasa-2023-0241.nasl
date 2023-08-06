# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0241");
  script_cve_id("CVE-2023-29197", "CVE-2023-36674", "CVE-2023-36675");
  script_tag(name:"creation_date", value:"2023-07-27 04:12:36 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-03 18:12:00 +0000 (Wed, 03 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0241");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0241.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32083");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/HVT3U3XYY35PSCIQPHMY4VQNF3Q6MHUO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2023-0241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"guzzlehttp/psr7 is a PSR-7 HTTP message library implementation in PHP.
Affected versions are subject to improper header parsing. An attacker
could sneak in a newline (\n) into both the header names and values.
While the specification states that \r\n\r\n is used to terminate the
header list, many servers in the wild will also accept \n\n
(CVE-2023-29197).

Manualthumb bypasses badFile lookup (CVE-2023-36674).

XSS in BlockLogFormatter due to unsafe message use (CVE-2023-36675).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.11~1.mga8", rls:"MAGEIA8"))) {
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
