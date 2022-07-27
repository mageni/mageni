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

CPE = "cpe:/a:loco_translate_project:loco_translate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147164");
  script_version("2021-11-16T03:39:55+0000");
  script_tag(name:"last_modification", value:"2021-11-16 11:18:47 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-16 02:50:27 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24721");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Loco Translate Plugin < 2.5.4 PHP Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/loco-translate/detected");

  script_tag(name:"summary", value:"The WordPress plugin Loco Translate is prone to a PHP injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin mishandles data inputs which get saved to a file,
  which can be renamed to an extension ending in .php, resulting in authenticated 'translator'
  users being able to inject PHP code into files ending with .php in web accessible locations.");

  script_tag(name:"affected", value:"WordPress Loco Translate version 2.5.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.5.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/bc7d4774-fce8-4b0b-8015-8ef4c5b02d38");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/loco-translate/#developers");

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

if (version_is_less(version: version, test_version: "2.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
