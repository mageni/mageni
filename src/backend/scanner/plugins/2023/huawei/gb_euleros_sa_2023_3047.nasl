# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3047");
  script_cve_id("CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0286", "CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466", "CVE-2023-2650", "CVE-2023-3817");
  script_tag(name:"creation_date", value:"2023-10-31 04:19:09 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-29 19:37:35 +0000 (Wed, 29 Mar 2023)");

  script_name("Huawei EulerOS: Security Advisory for linux-sgx (EulerOS-SA-2023-3047)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=(EULEROS\-2\.0SP11|EULEROS\-2\.0SP11\-X86_64)");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3047");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3047");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'linux-sgx' package(s) announced via the EulerOS-SA-2023-3047 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary: Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays. Where the key or parameters that are being checked have been obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs various checks on DH parameters. After fixing CVE-2023-3446 it was discovered that a large q parameter value can also trigger an overly long computation during some of these checks. A correct q value, if present, cannot be larger than the modulus p parameter, thus it is unnecessary to perform these checks if q is larger than p. An application that calls DH_check() and supplies a key or parameters obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function DH_check() is itself called by a number of other OpenSSL functions. An application calling any of those other functions may similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check(). Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the '-check' option. The OpenSSL SSL/TLS implementation is not affected by this issue. (CVE-2023-3817)

Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit. OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n' being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest passed data. Applications that call ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-sgx' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"procps-ng", rpm:"procps-ng~3.3.17~2.h15.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-ng-i18n", rpm:"procps-ng-i18n~3.3.17~2.h15.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libsgx-ae-le", rpm:"libsgx-ae-le~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsgx-aesm-launch-plugin", rpm:"libsgx-aesm-launch-plugin~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsgx-enclave-common", rpm:"libsgx-enclave-common~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsgx-launch", rpm:"libsgx-launch~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsgx-urts", rpm:"libsgx-urts~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-aesm-service", rpm:"sgx-aesm-service~2.15.1~1.h16.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
