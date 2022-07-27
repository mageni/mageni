###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sb_cisco-sa-20160803-rv110_130w2.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco RV110W, RV130W, and RV215W Routers Static Credential Vulnerability
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

CPE = "cpe:/h:cisco:small_business";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105847");
  script_cve_id("CVE-2015-6397");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco RV110W, RV130W, and RV215W Routers Static Credential Vulnerability ");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-rv110_130w2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"This vulnerability is fixed in the following firmware versions.

RV110W Wireless-N VPN Firewall, Release 1.2.1.7
RV130W Wireless-N Multifunction VPN Router, Release 1.0.3.16
RV215W Wireless-N VPN Router, Release 1.3.0.8");

  script_tag(name:"summary", value:"A vulnerability in the default account when used with a specific configuration of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N Multifunction VPN Router, and the Cisco RV215W Wireless-N VPN Router could allow an authenticated, remote attacker to gain root access to the device. The account could incorrectly be granted root privileges at authentication time.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-05 15:24:41 +0200 (Fri, 05 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_small_business_devices_snmp_detect.nasl");
  script_mandatory_keys("cisco/small_business/model", "cisco/small_business/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! model = get_kb_item( "cisco/small_business/model" ) ) exit( 0 );

if( model == 'RV110W' )
  if( version_in_range( version:version, test_version:"1.2.1", test_version2:'1.2.1.6') ) fix = '1.2.1.7';

if( model == 'RV130W' )
  if( version_in_range( version:version, test_version:"1.0.3", test_version2:'1.0.3.15') ) fix = '1.0.3.16';

if( model == 'RV215W' )
  if( version_in_range( version:version, test_version:"1.3.0", test_version2:'1.3.0.7') ) fix = '1.3.0.8';


report = report_fixed_ver(  installed_version:version, fixed_version:fix );
security_message( port:0, data:report );
exit( 99 );

