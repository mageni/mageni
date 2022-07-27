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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148392");
  script_version("2022-07-06T04:39:37+0000");
  script_tag(name:"last_modification", value:"2022-07-06 04:39:37 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-06 04:27:40 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2022-2097");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: AES OCB fails to encrypt some bytes (CVE-2022-2097) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AES OCB mode for 32-bit x86 platforms using the AES-NI assembly
  optimised implementation will not encrypt the entirety of the data under some circumstances. This
  could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the
  special case of 'in place' encryption, sixteen bytes of the plaintext would be revealed.

  Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both
  unaffected.");

  script_tag(name:"affected", value:"OpenSSL version 1.1.1 and 3.0.");

  script_tag(name:"solution", value:"Update to version 1.1.1q, 3.0.5 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220705.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1q")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1q", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
