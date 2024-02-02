# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0008");
  script_cve_id("CVE-2023-5981");
  script_tag(name:"creation_date", value:"2024-01-15 04:12:30 +0000 (Mon, 15 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:40:21 +0000 (Mon, 04 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0008)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0008");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0008.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32547");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/20/2");
  script_xref(name:"URL", value:"https://gnutls.org/security-new.html#GNUTLS-SA-2023-10-23");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the MGASA-2024-0008 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
A vulnerability was found that the response times to malformed
ciphertexts in RSA-PSK ClientKeyExchange differ from response times of
ciphertexts with correct PKCS#1 v1.5 padding. (CVE-2023-5981)");

  script_tag(name:"affected", value:"'gnutls' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-dane0", rpm:"lib64gnutls-dane0~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls30", rpm:"lib64gnutls30~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutlsxx30", rpm:"lib64gnutlsxx30~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-dane0", rpm:"libgnutls-dane0~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx30", rpm:"libgnutlsxx30~3.8.0~2.1.mga9", rls:"MAGEIA9"))) {
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
