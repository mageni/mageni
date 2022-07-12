###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_cisco-sa-20160113-ise.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco Identity Services Engine Unauthorized Access Vulnerability
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

CPE = "cpe:/a:cisco:identity_services_engine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105510");
  script_cve_id("CVE-2015-6323");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14181 $");

  script_name("Cisco Identity Services Engine Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-ise");

  script_tag(name:"impact", value:"A successful exploit may result in a complete compromise of the affected device.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An attacker who can connect to the Admin portal of an affected device could potentially
  exploit this vulnerability.");
  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");
  script_tag(name:"summary", value:"A vulnerability in the Admin portal of devices running Cisco Identity Services Engine (ISE)
  software could allow an unauthenticated, remote attacker to gain unauthorized access to an affected device.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-14 13:21:12 +0100 (Thu, 14 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version", "cisco_ise/patch");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! patch = get_kb_item( "cisco_ise/patch" ) ) exit( 0 );

# version is for example 1.1.4.218. But for this check we need only 1.1.4
v = split(version, sep:".", keep:FALSE );
version = v[0] + '.' + v[1] + '.' + v[2];

if( version_is_less( version:version, test_version:"1.2.0") ) fix = 'End-of-Life - Migrate.';

if( version == "1.2.0" )
  if( int( patch ) < 17 ) fix = '1.2.0 Patch 17';

if( version == "1.2.1" )
  if( int( patch ) < 8 ) fix = '1.2.1 Patch 8';

if( version == "1.3.0" )
  if( int( patch ) < 5 ) fix = '1.3 Patch 5';

if( version == "1.4.0" )
  if( int( patch ) < 4 ) fix = '1.4 Patch 4';

if( fix )
{
  report = 'Installed version: ' + version + '\n';
  if( int( patch ) > 0 ) report +=  'Installed patch:   ' + patch + '\n';
  report +=  'Fixed version:     ' + fix;

  security_message( port:0, data:report);
  exit( 0 );
}

exit( 99 );