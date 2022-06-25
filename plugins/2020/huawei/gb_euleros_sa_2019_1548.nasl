# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1548");
  script_version("2020-01-23T12:11:42+0000");
  script_cve_id("CVE-2007-5135", "CVE-2009-0590", "CVE-2009-1377", "CVE-2009-1386", "CVE-2009-4355", "CVE-2011-4108", "CVE-2012-2110", "CVE-2014-3507", "CVE-2014-3571", "CVE-2014-8176", "CVE-2014-8275", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0293", "CVE-2015-1789", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-4000", "CVE-2016-0703", "CVE-2019-1559");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:11:42 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:11:42 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for openssl (EulerOS-SA-2019-1548)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1548");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'openssl' package(s) announced via the EulerOS-SA-2019-1548 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was found in the session handling code of OpenSSL. This issue could possibly cause a multi-threaded TLS/SSL client using OpenSSL to double free session ticket data and crash.(CVE-2015-1791)

An out-of-bounds read flaw was found in the X509_cmp_time() function of OpenSSL, which is used to test the expiry dates of SSL/TLS certificates. An attacker could possibly use a specially crafted SSL/TLS certificate or CRL (Certificate Revocation List), which when parsed by an application would cause that application to crash.(CVE-2015-1789)

The ASN1_STRING_print_ex function in OpenSSL before 0.9.8k allows remote attackers to cause a denial of service (invalid memory access and application crash) via vectors that trigger printing of a (1) BMPString or (2) UniversalString with an invalid encoded length.(CVE-2009-0590)

An invalid-free flaw was found in the way OpenSSL handled certain DTLS handshake messages. A malicious DTLS client or server could send a specially crafted message to the peer, which could cause the application to crash or potentially result in arbitrary code execution.(CVE-2014-8176)

The DTLS implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f performs a MAC check only if certain padding is valid, which makes it easier for remote attackers to recover plaintext via a padding oracle attack.(CVE-2011-4108)

Off-by-one error in the SSL_get_shared_ciphers function in OpenSSL 0.9.7 up to 0.9.7l, and 0.9.8 up to 0.9.8f, might allow remote attackers to execute arbitrary code via a crafted packet that triggers a one-byte buffer underflow. NOTE: this issue was introduced as a result of a fix for CVE-2006-3738. As of 20071012, it is unknown whether code execution is possible.(CVE-2007-5135)

A NULL pointer dereference flaw was found in the DTLS implementation of OpenSSL. A remote attacker could send a specially crafted DTLS message, which would cause an OpenSSL server to crash.(CVE-2014-3571)

The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c in OpenSSL before 0.9.8v, 1.0.0 before 1.0.0i, and 1.0.1 before 1.0.1a does not properly interpret integer data, which allows remote attackers to conduct buffer overflow attacks, and cause a denial of service (memory corruption) or possibly have unspecified other impact, via crafted DER data, as demonstrated by an X.509 certificate or an RSA public key.(CVE-2012-2110)

It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2 connection handshakes that indicated non-zero clear key length for non-export cipher suites. An attacker could use this flaw to decrypt recorded SSLv2 sessions with the server ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'openssl' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2k~16.h5", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.2k~16.h5", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.2k~16.h5", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);