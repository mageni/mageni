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

CPE = "cpe:/a:hubspot:hubspot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148096");
  script_version("2022-05-11T06:16:48+0000");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 05:41:06 +0000 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-1239");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress HubSpot Plugin < 8.8.15 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/leadin/detected");

  script_tag(name:"summary", value:"The WordPress plugin HubSpot is prone to a server-side request
  forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate the proxy URL given to the proxy
  REST endpoint, which could allow users with the edit_posts capability (by default contributor and
  above) to perform SSRF attacks.");

  script_tag(name:"affected", value:"WordPress HubSpot plugin version 8.8.14 and prior.");

  script_tag(name:"solution", value:"Update to version 8.8.15 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4ad2bb96-87a4-4590-a058-b03b33d2fcee");

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

if (version_is_less(version: version, test_version: "8.8.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
