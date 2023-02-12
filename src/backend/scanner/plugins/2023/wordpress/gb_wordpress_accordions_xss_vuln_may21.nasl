# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170295");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2020-05-29 09:39:15 +0000 (Fri, 29 May 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 18:28:00 +0000 (Fri, 21 May 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-24283");

  script_name("WordPress Accordion Plugin < 2.2.30 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/accordions/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Accordion' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The tab GET parameter of the settings page is not sanitised or
  escaped when being output back in an HTML attribute.");

  script_tag(name:"affected", value:"WordPress Accordion plugin prior to version 2.2.30.");

  script_tag(name:"solution", value:"Update to version 2.2.30 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/6ccd9990-e15f-4800-b499-f7c74b480051");

  exit(0);
}

CPE = "cpe:/a:pickplugins:accordion";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.2.30" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.30", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
