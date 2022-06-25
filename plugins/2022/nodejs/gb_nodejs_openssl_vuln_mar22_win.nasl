# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113853");
  script_version("2022-03-18T12:51:52+0000");
  script_tag(name:"last_modification", value:"2022-03-18 12:51:52 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-18 12:42:42 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-0778");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x < 12.22.11, 14.x < 14.19.1, 16.x < 16.14.2, 17.x < 17.7.2 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability in
  OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaw exists in OpenSSL as used by Node.js:

  The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it
  to loop forever for non-prime moduli.

  Internally this function is used when parsing certificates that contain elliptic curve public
  keys in compressed form or explicit elliptic curve parameters with a base point encoded in
  compressed form.

  It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit
  curve parameters.

  Since certificate parsing happens prior to verification of the certificate signature, any process
  that parses an externally supplied certificate may thus be subject to a denial of service attack.
  The infinite loop can also be reached when parsing crafted private keys as they can contain
  explicit elliptic curve parameters.

  Thus vulnerable situations include:

  - TLS clients consuming server certificates

  - TLS servers consuming client certificates

  - Hosting providers taking certificates or private keys from customers

  - Certificate authorities parsing certification requests from subscribers

  - Anything else which parses ASN.1 elliptic curve parameters

  Also any other applications that use the BN_mod_sqrt() where the attacker can control the
  parameter values are vulnerable to this DoS issue.

  In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the
  certificate which makes it slightly harder to trigger the infinite loop. However any operation
  which requires the public key from the certificate will trigger the infinite loop. In particular
  the attacker can use a self-signed certificate to trigger the loop during verification of the
  certificate signature.");

  script_tag(name:"affected", value:"Node.js version 12.x prior to 12.22.11, 14.x prior to 14.19.1,
  16.x prior to 16.14.2 and 17.x prior to 17.7.2.");

  script_tag(name:"solution", value:"Update to version 12.22.11, 14.19.1, 16.14.2, 17.7.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/mar-2022-security-releases/");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220315.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.22.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.22.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.14.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.14.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
