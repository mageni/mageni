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

CPE = "cpe:/a:contact_form_7_captcha_project:contact_form_7_captcha";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126075");
  script_version("2022-07-18T14:04:03+0000");
  script_tag(name:"last_modification", value:"2022-07-18 14:04:03 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-18 11:52:40 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-2187");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Contact Form 7 Captcha Plugin < 0.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/contact-form-7-simple-recaptcha/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Contact Form 7 Captcha' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape the $_SERVER[REQUEST_URI] parameter
  before outputting it back in an attribute, which could lead to Reflected Cross-Site Scripting
  in old web browsers.");

  script_tag(name:"affected", value:"WordPress Contact Form 7 Captcha plugin prior to 0.1.2.");

  script_tag(name:"solution", value:"Update to version 0.1.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/contact-form-7-simple-recaptcha/#developers");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4fd2f1ef-39c6-4425-8b4d-1a332dabac8d");

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

if (version_is_less(version: version, test_version: "0.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
