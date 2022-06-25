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

CPE = "cpe:/a:wpfront:scroll_top";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146625");
  script_version("2021-09-03T13:01:29+0000");
  script_tag(name:"last_modification", value:"2021-09-06 10:19:05 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-03 11:09:57 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-27 14:49:00 +0000 (Fri, 27 Aug 2021)");

  script_cve_id("CVE-2021-24564");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WPFront Scroll Top Plugin < 2.0.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpfront-scroll-top/detected");

  script_tag(name:"summary", value:"The WordPress plugin WPFront Scroll Top is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise or escape its Image ALT setting
  before outputting it attributes, leading to an authenticated stored XSS issue even when the
  unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress WPFront Scroll Top plugin prior to version 2.0.7.");

  script_tag(name:"solution", value:"Update to version 2.0.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b25af0e1-392f-4305-ad44-50e64ef3dbdf");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wpfront-scroll-top/#developers");

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

if (version_is_less(version: version, test_version: "2.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
