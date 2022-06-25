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

CPE = "cpe:/a:ampforwp:accelerated_mobile_pages";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148251");
  script_version("2022-06-10T04:25:45+0000");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 14:35:00 +0200 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 20:15:00 +0000 (Thu, 24 Mar 2022)");

  script_cve_id("CVE-2021-23209");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Accelerated Mobile Pages Plugin <= 1.0.77.32 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/accelerated-mobile-pages/detected");

  script_tag(name:"summary", value:"The WordPress plugin Accelerated Mobile Pages is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  malicious content into an affected site.");

  script_tag(name:"affected", value:"WordPress Accelerated Mobile Pages plugin prior to version
  1.0.77.33.");

  script_tag(name:"solution", value:"Update to version 1.0.77.33 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/accelerated-mobile-pages/wordpress-amp-for-wp-accelerated-mobile-pages-plugin-1-0-77-32-multiple-authenticated-persistent-cross-site-scripting-xss-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.77.33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.77.33", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
