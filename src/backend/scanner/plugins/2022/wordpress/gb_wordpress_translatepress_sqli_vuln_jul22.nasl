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

CPE = "cpe:/a:cozmoslabs:translatepress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127200");
  script_version("2022-09-21T10:12:28+0000");
  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-20 06:10:45 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-3141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Translate Multilingual sites - TranslatePress Plugin < 2.3.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/translatepress-multilingual/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Translate Multilingual sites - TranslatePress'
  is prone to a SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By adding a new language (via the settings page) containing
  specific special characters, the backticks in the SQL query can be surpassed and a time-based
  blind payload can be injected.");

  script_tag(name:"affected", value:"WordPress 'Translate Multilingual sites - TranslatePress'
  plugin prior to version 2.3.3.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1fa355d1-cca8-4b27-9d21-0b420a2e1bf3");

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

if (version_is_less(version: version, test_version: "2.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
