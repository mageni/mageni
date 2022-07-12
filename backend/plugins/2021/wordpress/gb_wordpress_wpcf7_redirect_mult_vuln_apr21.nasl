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

CPE = "cpe:/a:querysol:redirection_for_contact_form_7";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146075");
  script_version("2021-06-04T03:54:14+0000");
  script_tag(name:"last_modification", value:"2021-06-04 10:13:25 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-04 03:17:46 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-24278", "CVE-2021-24279", "CVE-2021-24280", "CVE-2021-24281", "CVE-2021-24282");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Redirection for Contact Form 7 Plugin < 2.3.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpcf7-redirect/detected");

  script_tag(name:"summary", value:"WordPress Redirection for Contact Form 7 plugin is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2021-24278: Unauthenticated users can use the wpcf7r_get_nonce AJAX action to retrieve a
  valid nonce for any WordPress action/function.

  - CVE-2021-24279: Low level users, such as subscribers, could use the import_from_debug AJAX
  action to install any plugin from the WordPress repository.

  - CVE-2021-24280: Any authenticated user, such as a subscriber, could use the import_from_debug
  AJAX action to inject PHP objects.

  - CVE-2021-24281: Any authenticated user, such as a subscriber, could use the delete_action_post
  AJAX action to delete any post on a target site.

  - CVE-2021-24282: Any authenticated user, such as a subscriber, could use the various AJAX actions
  in the plugin to do a variety of things. For example, an attacker could use wpcf7r_reset_settings
  to reset the plugin's settings, wpcf7r_add_action to add actions to a form, and more.");

  script_tag(name:"affected", value:"WordPress Redirection for Contact Form 7 plugin version 2.3.3
  and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wpcf7-redirect/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/04/severe-vulnerabilities-patched-in-redirection-for-contact-form-7-plugin/");

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

if (version_is_less(version: version, test_version: "2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
