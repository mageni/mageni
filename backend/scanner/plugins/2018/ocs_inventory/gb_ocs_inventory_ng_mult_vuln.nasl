###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_ng_mult_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# OCS Inventory NG < 2.5 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112351");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 11:54:06 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-12482", "CVE-2018-12483", "CVE-2018-14473", "CVE-2018-14857");

  script_name("OCS Inventory NG < 2.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is affected by multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"OCS Inventory NG before version 2.5.");
  script_tag(name:"solution", value:"Upgrade to version 2.5 or later.");

  script_xref(name:"URL", value:"https://www.tarlogic.com/en/blog/vulnerabilities-in-ocs-inventory-2-4-1/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Aug/6");

  exit(0);
}

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
