# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117583");
  script_version("2021-07-30T07:03:45+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2014-3508", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3510");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20140806 - 1) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-3508: A flaw in OBJ_obj2txt may cause pretty printing functions such as
  X509_name_oneline, X509_name_print_ex et al. to leak some information from the stack. Applications
  may be affected if they echo pretty printing output to the attacker. OpenSSL SSL/TLS clients and
  servers themselves are not affected.

  - CVE-2014-3505: A Double Free was found when processing DTLS packets. An attacker can force an
  error condition which causes openssl to crash whilst processing DTLS packets due to memory being
  freed twice. This could lead to a Denial of Service attack.

  - CVE-2014-3506: A DTLS flaw leading to memory exhaustion was found. An attacker can force openssl
  to consume large amounts of memory whilst processing DTLS handshake messages. This could lead to a
  Denial of Service attack.

  - CVE-2014-3507: A DTLS memory leak from zero-length fragments was found. By sending carefully
  crafted DTLS packets an attacker could cause OpenSSL to leak memory.

  - CVE-2014-3510: A flaw in handling DTLS anonymous EC(DH) ciphersuites was found. OpenSSL DTLS
  clients enabling anonymous (EC)DH ciphersuites are subject to a denial of service attack. A
  malicious server can crash the client with a null pointer dereference (read) by specifying an
  anonymous (EC)DH ciphersuite and sending carefully crafted handshake messages.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8za, 1.0.0 through 1.0.0m and
  1.0.1 through 1.0.1h.");

  script_tag(name:"solution", value:"Update to version 0.9.8zb, 1.0.0n, 1.0.1i or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20140806.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "0.9.8", test_version2: "0.9.8za")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8zb", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.0", test_version2: "1.0.0m")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.0n", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.1", test_version2: "1.0.1h")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.1i", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);