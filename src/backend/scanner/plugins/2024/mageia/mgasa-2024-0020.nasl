# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0020");
  script_cve_id("CVE-2023-5678", "CVE-2023-6129", "CVE-2023-6237", "CVE-2024-0727");
  script_tag(name:"creation_date", value:"2024-02-05 04:11:46 +0000 (Mon, 05 Feb 2024)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 21:32:01 +0000 (Tue, 23 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0020");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0020.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32498");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20231106.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240109.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240115.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240125.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2024-0020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Excessive time spent in DH check / generation with large Q parameter
value. (CVE-2023-5678)
POLY1305 MAC implementation corrupts vector registers on PowerPC.
(CVE-2023-6129)
Excessive time spent checking invalid RSA public keys. (CVE-2023-6237)
PKCS12 Decoding crashes. (CVE-2024-0727)");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl3", rpm:"lib64openssl3~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~3.0.12~1.1.mga9", rls:"MAGEIA9"))) {
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
