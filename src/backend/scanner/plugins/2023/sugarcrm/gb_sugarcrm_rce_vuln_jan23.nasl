# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.126295");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-12 10:00:46 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-22952");

  script_name("SugarCRM 11.0.x < 11.0.5, 12.0.x < 12.0.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A RCE has been identified in the EmailTemplates.");

  script_tag(name:"affected", value:"SugarCRM versions 11.0.x prior to 11.0.5 and 12.0.x prior
  to 12.0.2.");

  script_tag(name:"solution", value:"Update to version 11.0.5, 12.0.2 or later.");

  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2023-001/");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2022/Dec/31");
  script_xref(name:"URL", value:"https://censys.io/tracking-a-sugarcrm-zero-day/");

  exit(0);
}

CPE = "cpe:/a:sugarcrm:sugarcrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0.0", test_version_up: "12.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
