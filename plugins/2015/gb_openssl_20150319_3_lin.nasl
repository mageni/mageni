# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806731");
  script_version("2021-07-29T12:32:36+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-29 12:32:36 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2015-11-26 11:33:57 +0530 (Thu, 26 Nov 2015)");

  script_cve_id("CVE-2015-0293", "CVE-2015-0289", "CVE-2015-0288", "CVE-2015-0287", "CVE-2015-0286",
                "CVE-2015-0209");

  script_bugtraq_id(73232, 73231, 73237, 73227, 73225, 73239);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20150319 - 3) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-0293: DoS via reachable assert in SSLv2 servers. A malicious client can trigger an
  OPENSSL_assert in servers that both support SSLv2 and enable export cipher suites by sending a
  specially crafted SSLv2 CLIENT-MASTER-KEY message.

  - CVE-2015-0289: PKCS#7 NULL pointer dereference. The PKCS#7 parsing code does not handle missing
  outer ContentInfo correctly. An attacker can craft malformed ASN.1-encoded PKCS#7 blobs with
  missing content and trigger a NULL pointer dereference on parsing. Applications that verify PKCS#7
  signatures, decrypt PKCS#7 data or otherwise parse PKCS#7 structures from untrusted sources are
  affected. OpenSSL clients and servers are not affected.

  - CVE-2015-0288: X509_to_X509_REQ NULL pointer deref. The function X509_to_X509_REQ will crash
  with a NULL pointer dereference if the certificate key is invalid. This function is rarely used in
  practice.

  - CVE-2015-0287: ASN.1 structure reuse memory corruption. Reusing a structure in ASN.1 parsing may
  allow an attacker to cause memory corruption via an invalid write. Such reuse is and has been
  strongly discouraged and is believed to be rare.

  - CVE-2015-0286: Segmentation fault in ASN1_TYPE_cmp. The function ASN1_TYPE_cmp will crash with
  an invalid read if an attempt is made to compare ASN.1 boolean types. Since ASN1_TYPE_cmp is used
  to check certificate signature algorithm consistency this can be used to crash any certificate
  verification operation and exploited in a DoS attack. Any application which performs certificate
  verification is vulnerable including OpenSSL clients and servers which enable client authentication.

  - CVE-2015-0209: Use After Free following d2i_ECPrivatekey error. A malformed EC private key file
  consumed via the d2i_ECPrivateKey function could cause a use after free condition. This, in turn,
  could cause a double free in several private key parsing functions (such as d2i_PrivateKey or
  EVP_PKCS82PKEY) and could lead to a DoS attack or memory corruption for applications that receive
  EC private keys from untrusted sources. This scenario is considered rare.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service or execute arbitrary code or possibly
  have unspecified other impact .");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8ze, 1.0.0 through 1.0.0q,
  1.0.1 through 1.0.1l and 1.0.2.");

  script_tag(name:"solution", value:"Update to version 0.9.8zf, 1.0.0r, 1.0.1m, 1.0.2a or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_xref(name:"URL", value:"https://bto.bluecoat.com/security-advisory/sa92");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"0.9.8", test_version2:"0.9.8ze")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8zf", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.0", test_version2:"1.0.0q")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.0r", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.1", test_version2:"1.0.1l")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.1m", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_is_equal(version:vers, test_version:"1.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2a", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);