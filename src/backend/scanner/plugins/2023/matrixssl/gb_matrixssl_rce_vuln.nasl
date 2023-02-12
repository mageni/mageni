# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:matrixssl:matrixssl";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124254");
  script_version("2023-01-18T10:11:02+0000");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 08:17:00 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-43974");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL 4.x < 4.6.0 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_matrixssl_http_detect.nasl");
  script_mandatory_keys("matrixssl/detected");

  script_tag(name:"summary", value:"MatrixSSL is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MatrixSSL has an integer overflow in matrixSslDecodeTls13. A
  remote attacker might be able to send a crafted TLS Message to cause a buffer overflow and
  achieve remote code execution.");

  script_tag(name:"affected", value:"MatrixSSL 4.x prior to version 4.6.0.");

  script_tag(name:"solution", value:"Update to version 4.6.0 or later.");

  script_xref(name:"URL", value:"https://www.telekom.com/resource/blob/1023574/cff397adaf5dca6c8bc590eafa1a4a02/dl-230109-cve-2022-43974-data.pdf");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/security/advisories/GHSA-fmwc-gwc5-2g29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
