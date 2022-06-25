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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1861");
  script_version("2020-01-23T12:24:58+0000");
  script_cve_id("CVE-2014-3571", "CVE-2015-0292", "CVE-2015-1789", "CVE-2015-3195", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2177");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:24:58 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:24:58 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for openssl098e (EulerOS-SA-2019-1861)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1861");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'openssl098e' package(s) announced via the EulerOS-SA-2019-1861 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer underflow flaw, leading to a buffer overflow, was found in the way OpenSSL decoded malformed Base64-encoded inputs. An attacker able to make an application using OpenSSL decode a specially crafted Base64-encoded input (such as a PEM file) could use this flaw to cause the application to crash. Note: this flaw is not exploitable via the TLS/SSL protocol because the data being transferred is not Base64-encoded.(CVE-2015-0292)

An out-of-bounds read flaw was found in the X509_cmp_time() function of OpenSSL, which is used to test the expiry dates of SSL/TLS certificates. An attacker could possibly use a specially crafted SSL/TLS certificate or CRL (Certificate Revocation List), which when parsed by an application would cause that application to crash.(CVE-2015-1789)

A memory leak vulnerability was found in the way OpenSSL parsed PKCS#7 and CMS data. A remote attacker could use this flaw to cause an application that parses PKCS#7 or CMS data from untrusted sources to use an excessive amount of memory and possibly crash.(CVE-2015-3195)

OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a crafted DTLS message that is processed with a different read operation for the handshake header than for the handshake body, related to the dtls1_get_record function in d1_pkt.c and the ssl3_read_n function in s3_pkt.c.(CVE-2014-3571)

OpenSSL through 1.0.2h incorrectly uses pointer arithmetic for heap-buffer boundary checks, which might allow remote attackers to cause a denial of service (integer overflow and application crash) or possibly have unspecified other impact by leveraging unexpected malloc behavior, related to s3_srvr.c, ssl_sess.c, and t1_lib.c.(CVE-2016-2177)

An integer overflow flaw, leading to a buffer overflow, was found in the way the EVP_EncodeUpdate() function of OpenSSL parsed very large amounts of input data. A remote attacker could use this flaw to crash an application using OpenSSL or, possibly, execute arbitrary code with the permissions of the user running that application.(CVE-2016-2105)

An integer overflow flaw, leading to a buffer overflow, was found in the way the EVP_EncryptUpdate() function of OpenSSL parsed very large amounts of input data. A remote attacker could use this flaw to crash an application using OpenSSL or, possibly, execute arbitrary code with the permissions of the user running that application.(CVE-2016-2106)

A flaw was found in the way OpenSSL encoded certain ASN.1 data structures. An attacker could use this flaw to create  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'openssl098e' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.3.h6", rls:"EULEROS-2.0SP2"))) {
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