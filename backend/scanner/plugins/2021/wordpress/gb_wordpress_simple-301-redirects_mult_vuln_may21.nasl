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

CPE = "cpe:/a:betterlinks:simple-301-redirects";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146122");
  script_version("2021-06-15T03:50:59+0000");
  script_tag(name:"last_modification", value:"2021-06-15 10:41:11 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-15 03:39:07 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_cve_id("CVE-2021-24352", "CVE-2021-24353", "CVE-2021-24354", "CVE-2021-24355", "CVE-2021-24356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Simple 301 Redirects by BetterLinks Plugin < 2.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/simple-301-redirects/detected");

  script_tag(name:"summary", value:"WordPress Simple 301 Redirects by BetterLinks plugin is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2021-24352: The export_data function has no capability or nonce checks making it possible
  for unauthenticated users to export a site's redirects.

  - CVE-2021-24353: The import_data function has no capability or nonce checks making it possible
  for unauthenticated users to import a set of site redirects.

  - CVE-2021-24354: A lack of capability checks and insufficient nonce check on the AJAX action
  makes it possible for authenticated users to install arbitrary plugins on vulnerable sites.

  - CVE-2021-24355: The lack of capability checks and insufficient nonce check on the AJAX actions,
  simple301redirects/admin/get_wildcard and simple301redirects/admin/wildcard, makes it possible
  for authenticated users to retrieve and update the wildcard value for redirects.

  - CVE-2021-24356: The lack of capability checks and insufficient nonce check on the AJAX action,
  simple301redirects/admin/activate_plugin, makes it possible for authenticated users to activate
  arbitrary plugins installed on vulnerable sites.");

  script_tag(name:"affected", value:"WordPress Simple 301 Redirects by BetterLinks plugin prior to
  version 2.0.4.");

  script_tag(name:"solution", value:"Update to version 2.0.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/simple-301-redirects/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/05/severe-vulnerabilities-patched-in-simple-301-redirects-by-betterlinks-plugin/");

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

if (version_is_less(version: version, test_version: "2.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
