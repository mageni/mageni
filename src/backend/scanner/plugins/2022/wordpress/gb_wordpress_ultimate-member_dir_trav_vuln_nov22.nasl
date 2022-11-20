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

CPE = "cpe:/a:ultimatemember:ultimate-member";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127254");
  script_version("2022-11-17T14:16:28+0000");
  script_tag(name:"last_modification", value:"2022-11-17 14:16:28 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-17 09:28:15 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-3966");

  script_name("WordPress Ultimate Member Plugin < 2.5.1 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ultimate Member' is prone to a directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The manipulation of the tpl argument in the Template Handler
  component leads to a remote directory traversal.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin prior to version 2.5.1.");

  script_tag(name:"solution", value:"Update to version 2.5.1 or later.");

  script_xref(name:"URL", value:"https://vuldb.com/?id.213545");
  script_xref(name:"URL", value:"https://github.com/ultimatemember/ultimatemember/releases/tag/2.5.1");

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

if (version_is_less(version: version, test_version: "2.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.1", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
