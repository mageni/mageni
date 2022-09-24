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

CPE = "cpe:/a:wpvivid:migration%2c_backup%2c_staging";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127199");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-19 09:05:08 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-2863");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Migration, Backup, Staging - WPvivid Plugin < 0.9.76 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpvivid-backuprestore/detected");

  script_tag(name:"summary", value:"The WordPress plugin Migration, Backup, Staging - WPvivid is
  prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and validate a parameter before
  using it to read the content of a file, allowing high privilege users to read any file from the
  web server via a Traversal attack.");

  script_tag(name:"affected", value:"WordPress Migration, Backup, Staging - WPvivid plugin prior to
  version 0.9.76.");

  script_tag(name:"solution", value:"Update to version 0.9.76 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/cb6a3304-2166-47a0-a011-4dcacaa133e5");

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

if (version_is_less(version: version, test_version: "0.9.76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.76", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
