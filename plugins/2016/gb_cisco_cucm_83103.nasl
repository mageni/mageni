###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_83103.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco Unified Communications Manager Information Disclosure Vulnerability
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105541");
  script_bugtraq_id(83103);
  script_cve_id("CVE-2016-1319");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12149 $");

  script_name("Multiple Cisco Unified Products Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83103");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160208-ucm");

  script_tag(name:"impact", value:"An attacker can exploit this issue to obtain sensitive information.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to an encryption key that can be read in plain text.");
  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"Multiple Cisco Unified Products are prone to an information-disclosure vulnerability.");
  script_tag(name:"affected", value:"Cisco Unified Communications Manager (CallManager) Releases 10.5(2.12901.1), 10.5(2.10000.5), 11.0(1.10000.10), and 9.1(2.10000.28)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-12 14:47:29 +0100 (Fri, 12 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

# example for detected version: 11.0.1.10000-10
vers = str_replace( string:vers, find:"-", replace:"." );

if( vers =~ '^10\\.5\\.2' )
{
  if( version_is_less( version:vers, test_version:"10.5.2.13050.1" ) )
    fix = '10.5(2.13050.1)';
}

if( vers =~ '^11\\.0\\.1' )
{
  if( version_is_less( version:vers, test_version:"11.0.1.21016.3" ) )
    fix = '11.0(1.21016.3)';
}

if( vers =~ '^9\\.1\\.2' )
{
  if( version_is_less( version:vers, test_version:"9.1.2.15116.1" ) )
    fix = '9.1(2.15116.1)';
}

if( fix )
{
  report = report_fixed_ver(  installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
