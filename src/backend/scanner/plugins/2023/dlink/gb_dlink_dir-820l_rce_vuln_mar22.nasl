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

CPE = "cpe:/o:d-link:dir-820l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170321");
  script_version("2023-02-27T10:17:28+0000");
  script_tag(name:"last_modification", value:"2023-02-27 10:17:28 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-23 20:23:43 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 13:08:00 +0000 (Mon, 04 Apr 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-26258");

  script_name("D-Link DIR-820L Devices RCE Vulnerability (Mar 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-820L devices are prone to a remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"D-Link DIR-820L was discovered to contain a remote command
  execution vulnerability via the Device Name parameter in /lan.asp.");

  script_tag(name:"affected", value:"D-Link DIR-820L devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-820L reached its End-of-Support Date in 01.11.2017, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10295");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/pages/product.aspx?id=00c2150966b046b58ba95d8ae3a8f73d");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
