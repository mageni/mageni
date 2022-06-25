###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucmim_CSCuw31632.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Cisco Unified Communications Manager IM and Presence Service REST API Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:cisco:unified_communications_manager_im_and_presence_service";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105545");
  script_bugtraq_id(76944);
  script_cve_id("CVE-2015-6310");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 13999 $");

  script_name("Cisco Unified Communications Manager IM and Presence Service EST API Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76944");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20151002-CVE-2015-6310");

  script_tag(name:"impact", value:"Attackers can exploit this issue to restart the affected service and cause a denial of service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"summary", value:"Cisco Unified Communications Manager IM and Presence Service is prone to a denial-of-service vulnerability.");

  script_tag(name:"affected", value:"Versions 10.5 before 10.5(2.23000.1), 11.0 before 11.0(1.11000.1) and 9.1 before 9.1(1.81900.5).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-15 12:13:16 +0100 (Mon, 15 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucmim_version.nasl");
  script_mandatory_keys("cisco/cucmim/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version( cpe:CPE) ) exit( 0 );

# For example: 10.0.1.10000-26
vers = str_replace( string:vers, find:"-", replace:"." );

if( vers =~ "^10\.5" )
  if( version_is_less( version:vers, test_version:"10.5.2.23000.1" ) ) fix = '10.5(2.23000.1)';

if( vers =~ "^11\.0" )
  if( version_is_less( version:vers, test_version:"11.0.1.11000.1" ) ) fix = '11.0(1.11000.1)';

if( vers =~ "^9\.1" )
  if( version_is_less( version:vers, test_version:"9.1.1.81900.5" ) ) fix = '9.1(1.81900.5)';

if( fix )
{
  report = report_fixed_ver(  installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );