###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_cisco-sa-20160113-wlc.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Wireless LAN Controller Unauthorized Access Vulnerability
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
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105511");
  script_cve_id("CVE-2015-6314");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-14 14:09:16 +0100 (Thu, 14 Jan 2016)");
  script_name("Cisco Wireless LAN Controller Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-wlc");

  script_tag(name:"summary", value:"Devices running Cisco Wireless LAN Controller (WLC) contain an unauthorized access vulnerability.");
  script_tag(name:"impact", value:"This vulnerability could allow an unauthenticated, remote attacker to modify the configuration of the device.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"affected", value:"Cisco Wireless LAN Controller (WLC) software versions 7.6.120.0 or later, 8.0 or later, or 8.1 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/o:cisco:wireless_lan_controller_software';

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! model = get_kb_item( "cisco_wlc/model" ) ) exit( 0 );

if( model !~ '25[0-9][0-9]' && model !~ '55[0-9][0-9]' && model !~ '85[0-9][0-9]' && model !~ '75[0-9][0-9]' && "AIR-CTVM" >!< model ) exit( 99 );

if( vers =~ '^7\\.6' )
{
  if( version_is_less( version:vers, test_version:"7.6.120.0" ) ) exit( 99 );
  fix = 'Ask vendor';
}

if( vers =~ '^8\\.0' )
  if( version_is_less( version:vers, test_version:"8.0.121.0" ) ) fix = '8.0.121.0';

if( vers =~ '^8\\.1' )
  if( version_is_less( version:vers, test_version:"8.1.131.0" ) ) fix = '8.1.131.0';

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

