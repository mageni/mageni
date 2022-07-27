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

CPE = "cpe:/a:yikes:yikes-inc-easy-mailchimp-extender";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147510");
  script_version("2022-01-26T04:29:16+0000");
  script_tag(name:"last_modification", value:"2022-01-27 13:28:49 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-26 03:58:56 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-24985");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Easy Forms for Mailchimp Plugin < 6.8.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/yikes-inc-easy-mailchimp-extender/detected");

  script_tag(name:"summary", value:"The WordPress plugin Easy Forms for Mailchimp is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape the field_name and
  field_type parameters before outputting them back in attributes, leading to reflected XSS issues.");

  script_tag(name:"affected", value:"WordPress Easy Forms for Mailchimp plugin version 6.8.5 and
  prior.");

  script_tag(name:"solution", value:"Update to version 6.8.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/50be0ebf-fe6d-41e5-8af9-0d74f33aeb57");

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

if (version_is_less(version: version, test_version: "6.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
