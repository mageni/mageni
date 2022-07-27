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
  script_oid("1.3.6.1.4.1.25623.1.0.117581");
  script_version("2021-07-29T09:13:10+0000");
  script_tag(name:"last_modification", value:"2021-07-29 09:13:10 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-0733");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Security Bypass Vulnerability (20180327) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Because of an implementation bug the PA-RISC CRYPTO_memcmp
  function is effectively reduced to only comparing the least significant bit of each byte. This
  allows an attacker to forge messages that would be considered as authenticated in an amount of
  tries lower than that guaranteed by the security claims of the scheme.");

  script_tag(name:"affected", value:"OpenSSL version 1.1.0 through 1.1.0g.

  The affected module can only be compiled by the HP-UX assembler, so that only HP-UX PA-RISC
  targets are affected.");

  script_tag(name:"solution", value:"Update to version 1.1.0h or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180327.txt");

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

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.0g")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.0h", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);