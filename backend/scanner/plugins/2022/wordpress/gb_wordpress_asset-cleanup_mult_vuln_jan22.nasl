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

CPE = "cpe:/a:wpchill:download_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147605");
  script_version("2022-02-08T04:08:14+0000");
  script_tag(name:"last_modification", value:"2022-02-08 11:07:39 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 03:25:06 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24937", "CVE-2021-24983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Asset CleanUp: Page Speed Booster Plugin < 1.3.8.5 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-asset-clean-up/detected");

  script_tag(name:"summary", value:"The WordPress plugin Asset CleanUp: Page Speed Booster is prone
  to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-24937: The plugin does not escape the wpacu_selected_sub_tab_area parameter before
  outputting it back in an attribute in an admin page, leading to a reflected XSS issue

  - CVE-2021-24983: The plugin does not sanitise and escape POSted parameters sent to the
  wpassetcleanup_fetch_active_plugins_icons AJAX action (available to admin users), leading to a
  reflected XSS issue");

  script_tag(name:"affected", value:"WordPress Asset CleanUp: Page Speed Booster version 1.3.8.4
  and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.8.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/dde3c119-dad9-4205-a931-d49bbf3b6b87");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/31fdabb0-bc74-4d25-b0cd-c872aae6cb2f");

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

if (version_is_less(version: version, test_version: "1.3.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
