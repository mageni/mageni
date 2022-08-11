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
  script_oid("1.3.6.1.4.1.25623.1.0.112912");
  script_version("2021-08-13T08:09:25+0000");
  script_tag(name:"last_modification", value:"2021-08-13 10:29:13 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2003-0078");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Timing-based attacks on SSL/TLS with CBC encryption (CVE-2003-0078) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to timing-based attacks on SSL/TLS with CBC encryption.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ssl3_get_record in s3_pkt.c for OpenSSL does not perform a MAC
  computation if an incorrect block cipher padding is used, which causes an information leak
  (timing discrepancy) that may make it easier to launch cryptographic attacks that rely on
  distinguishing between padding and MAC verification errors, possibly leading to extraction of
  the original plaintext, aka the 'Vaudenay timing attack'.");

  script_tag(name:"impact", value:"An active attacker can substitute specifically made-up
  ciphertext blocks for blocks sent by legitimate SSL/TLS parties and measure the time
  until a response arrives: SSL/TLS includes data authentication to ensure that such
  modified ciphertext blocks will be rejected by the peer (and the connection aborted),
  but the attacker may be able to use timing observations to distinguish between two
  different error cases, namely block cipher padding errors and MAC verification errors.
  This is sufficient for an adaptive attack that finally can obtain the complete plaintext block.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.6 through 0.9.6h and 0.9.7.");

  script_tag(name:"solution", value:"Update OpenSSL to version 0.9.6.i, 0.9.7a or later. See the references for
  more details.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20030219.txt");

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

if (version_in_range(version: version, test_version: "0.9.6", test_version2: "0.9.6h")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.6i", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "0.9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.7a", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
