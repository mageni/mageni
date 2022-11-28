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

CPE = "cpe:/a:contact_form_7_database_addon:contact_form_7_database_addon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127255");
  script_version("2022-11-22T10:53:07+0000");
  script_tag(name:"last_modification", value:"2022-11-22 10:53:07 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-22 08:26:35 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-3634");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Contact Form 7 Database Addon Plugin < 1.2.6.5 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/contact-form-cfdb7/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Contact Form 7 Database Addon' is prone
  to a CSV injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate data when output it back in a CSV
  file.");

  script_tag(name:"affected", value:"WordPress Contact Form 7 Database Addon plugin prior to
  version 1.2.6.5.");

  script_tag(name:"solution", value:"Update to version 1.2.6.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b5eeefb0-fb5e-4ca6-a6f0-67f4be4a2b10");

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

if (version_is_less(version: version, test_version: "1.2.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
