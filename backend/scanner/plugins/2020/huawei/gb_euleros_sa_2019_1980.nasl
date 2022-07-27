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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1980");
  script_version("2020-01-23T12:29:31+0000");
  script_cve_id("CVE-2015-0204", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-1789", "CVE-2015-1790");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:29:31 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:29:31 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for openssl098e (EulerOS-SA-2019-1980)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1980");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'openssl098e' package(s) announced via the EulerOS-SA-2019-1980 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL would accept ephemeral RSA keys when using non-export RSA cipher suites. A malicious server could make a TLS/SSL client using OpenSSL use a weaker key exchange method.(CVE-2015-0204)

A NULL pointer dereference flaw was found in OpenSSL's X.509 certificate handling implementation. A specially crafted X.509 certificate could cause an application using OpenSSL to crash if the application attempted to convert the certificate to a certificate request.(CVE-2015-0288)

A NULL pointer dereference was found in the way OpenSSL handled certain PKCS#7 inputs. An attacker able to make an application using OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input could cause that application to crash. TLS/SSL clients and servers using OpenSSL were not affected by this flaw.(CVE-2015-0289)

An integer underflow flaw, leading to a buffer overflow, was found in the way OpenSSL decoded malformed Base64-encoded inputs. An attacker able to make an application using OpenSSL decode a specially crafted Base64-encoded input (such as a PEM file) could use this flaw to cause the application to crash. Note: this flaw is not exploitable via the TLS/SSL protocol because the data being transferred is not Base64-encoded.(CVE-2015-0292)

An out-of-bounds read flaw was found in the X509_cmp_time() function of OpenSSL, which is used to test the expiry dates of SSL/TLS certificates. An attacker could possibly use a specially crafted SSL/TLS certificate or CRL (Certificate Revocation List), which when parsed by an application would cause that application to crash.(CVE-2015-1789)

A NULL pointer dereference was found in the way OpenSSL handled certain PKCS#7 inputs. An attacker able to make an application using OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input could cause that application to crash. TLS/SSL clients and servers using OpenSSL were not affected by this flaw.(CVE-2015-1790)");

  script_tag(name:"affected", value:"'openssl098e' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.3.h6.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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