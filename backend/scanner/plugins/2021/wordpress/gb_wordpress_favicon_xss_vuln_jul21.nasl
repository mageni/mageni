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

CPE = "cpe:/a:realfavicongenerator:favicon_by_realfavicongenerator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146621");
  script_version("2021-09-06T09:01:34+0000");
  script_tag(name:"last_modification", value:"2021-09-06 10:19:05 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-03 09:07:18 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-02 13:59:00 +0000 (Thu, 02 Sep 2021)");

  script_cve_id("CVE-2021-24437");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Favicon by RealFaviconGenerator Plugin < 1.3.22 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/favicon-by-realfavicongenerator/detected");

  script_tag(name:"summary", value:"The WordPress plugin Favicon by RealFaviconGenerator is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise or escape one of its parameter
  before outputting it back in the response, leading to a reflected XSS which is executed in the
  context of a logged administrator.");

  script_tag(name:"affected", value:"WordPress Favicon by RealFaviconGenerator plugin version
  1.3.21 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.22 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ed9d26be-cc96-4274-a05b-0b7ad9d8cfd9");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/favicon-by-realfavicongenerator/#developers");

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

if (version_is_less(version: version, test_version: "1.3.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
