# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0031");
  script_cve_id("CVE-2024-0553", "CVE-2024-0567");
  script_tag(name:"creation_date", value:"2024-02-09 04:12:12 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-24 14:13:44 +0000 (Wed, 24 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0031");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0031.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32755");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/01/19/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the MGASA-2024-0031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
A vulnerability was found in GnuTLS, where a cockpit (which uses gnuTLS)
rejects a certificate chain with distributed trust. This issue occurs
when validating a certificate chain with cockpit-certificate-ensure.
This flaw allows an unauthenticated, remote client or attacker to
initiate a denial of service attack. (CVE-2024-0567)
A vulnerability was found in GnuTLS. The response times to malformed
ciphertexts in RSA-PSK ClientKeyExchange differ from response times of
ciphertexts with correct PKCS#1 v1.5 padding. This issue may allow a
remote attacker to perform a timing side-channel attack in the RSA-PSK
key exchange, potentially leading to the leakage of sensitive data.
CVE-2024-0553 is designated as an incomplete resolution for
CVE-2023-5981. (CVE-2024-0553)");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-dane0", rpm:"lib64gnutls-dane0~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls30", rpm:"lib64gnutls30~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutlsxx30", rpm:"lib64gnutlsxx30~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-dane0", rpm:"libgnutls-dane0~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx30", rpm:"libgnutlsxx30~3.8.0~2.2.mga9", rls:"MAGEIA9"))) {
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
