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

CPE = "cpe:/a:publishpress:post_expirator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147166");
  script_version("2021-11-16T03:39:55+0000");
  script_tag(name:"last_modification", value:"2021-11-16 11:18:47 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-16 03:27:02 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24783");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Post Expirator Plugin < 2.6.0 Arbitrary Post Schedule Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/post-expirator/detected");

  script_tag(name:"summary", value:"The WordPress plugin Post Expirator is prone to an arbitrary
  post schedule deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have proper capability checks in place,
  which could allow users with a role as low as Contributor to schedule deletion of arbitrary posts.");

  script_tag(name:"affected", value:"WordPress Post Expirator version 2.5.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.6.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/de51b970-ab13-41a6-a479-a92cd0e70b71");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/post-expirator/#developers");

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

if (version_is_less(version: version, test_version: "2.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
