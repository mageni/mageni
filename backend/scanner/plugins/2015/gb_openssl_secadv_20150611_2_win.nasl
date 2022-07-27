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
  script_oid("1.3.6.1.4.1.25623.1.0.806744");
  script_version("2021-07-29T13:31:06+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-29 13:31:06 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2015-12-01 09:41:47 +0530 (Tue, 01 Dec 2015)");

  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792");

  script_bugtraq_id(75156, 75157, 75161, 75154);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20150611 - 2) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-1789: X509_cmp_time does not properly check the length of the ASN1_TIME string and can
  read a few bytes out of bounds. In addition, X509_cmp_time accepts an arbitrary number of
  fractional seconds in the time string. An attacker can use this to craft malformed certificates
  and CRLs of various sizes and potentially cause a segmentation fault, resulting in a DoS on
  applications that verify certificates or CRLs. TLS clients that verify CRLs are affected. TLS
  clients and servers with client authentication enabled may be affected if they use custom
  verification callbacks.

  - CVE-2015-1790: The PKCS#7 parsing code does not handle missing inner EncryptedContent correctly.
  An attacker can craft malformed ASN.1-encoded PKCS#7 blobs with missing content and trigger a NULL
  pointer dereference on parsing. Applications that decrypt PKCS#7 data or otherwise parse PKCS#7
  structures from untrusted sources are affected. OpenSSL clients and servers are not affected.

  - CVE-2015-1791: If a NewSessionTicket is received by a multi-threaded client when attempting to
  reuse a previous ticket then a race condition can occur potentially leading to a double free of
  the ticket data.

  - CVE-2015-1792: When verifying a signedData message the CMS code can enter an infinite loop if
  presented with an unknown hash function OID. This can be used to perform denial of service against
  any system which verifies signedData messages using the CMS code.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8zf, 1.0.0 through 1.0.0r,
  1.0.1 through 1.0.1m and 1.0.2 through 1.0.2a.");

  script_tag(name:"solution", value:"Update to version 0.9.8zg, 1.0.0s, 1.0.1n, 1.0.2b later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150611.txt");

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

if(version_in_range(version:vers, test_version:"0.9.8", test_version2:"0.9.8zf")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8zg", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.0", test_version2:"1.0.0r")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.0s", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.1", test_version2:"1.0.1m")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.1n", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.2", test_version2:"1.0.2a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2b", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);