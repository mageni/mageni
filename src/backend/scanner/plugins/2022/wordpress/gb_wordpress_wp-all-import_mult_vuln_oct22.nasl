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

CPE = "cpe:/a:soflyy:wp_all_import";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127246");
  script_version("2022-11-08T12:34:13+0000");
  script_tag(name:"last_modification", value:"2022-11-08 12:34:13 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-08 11:16:40 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-2711", "CVE-2022-3418");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Import any XML or CSV File to WordPress Plugin < 3.6.9 Multiple File Upload Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-all-import/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Import any XML or CSV File to WordPress'
  is prone to multiple file upload vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2711: The plugin is not validating the paths of files contained in uploaded zip
  archives, allowing highly privileged users, such as admins, to write arbitrary files to any part
  of the file system accessible by the web server via a path traversal vector.

  - CVE-2022-3418: The plugin is not properly filtering which file extensions are allowed to be
  imported on the server, which could allow administrators in multi-site WordPress installations to
  upload arbitrary files.");

  script_tag(name:"affected", value:"WordPress Import any XML or CSV File to WordPress plugin
  prior to version 3.6.9.");

  script_tag(name:"solution", value:"Update to version 3.6.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/11e73c23-ff5f-42e5-a4b0-0971652dcea1");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ccbb74f5-1b8f-4ea6-96bc-ddf62af7f94d");

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

if (version_is_less(version: version, test_version: "3.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
