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

CPE = "cpe:/a:cesanta:mongoose";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147688");
  script_version("2022-02-23T04:20:23+0000");
  script_tag(name:"last_modification", value:"2022-02-23 11:20:38 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-23 04:13:56 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-25299");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mongoose Web Server < 7.6 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_mongoose_web_server_http_detect.nasl");
  script_mandatory_keys("cesanta/mongoose/detected");

  script_tag(name:"summary", value:"Mongoose Web Server is prone to an arbitrary file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The unsafe handling of file names during upload using
  mg_http_upload() method may enable attackers to write files to arbitrary locations outside the
  designated target folder.");

  script_tag(name:"affected", value:"Mongoose Web Server version 7.5 and prior.");

  script_tag(name:"solution", value:"Update to version 7.6 or later.");

  script_xref(name:"URL", value:"https://security.snyk.io/vuln/SNYK-UNMANAGED-CESANTAMONGOOSE-2404180");

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

if (version_is_less(version: version, test_version: "7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
