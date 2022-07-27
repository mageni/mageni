###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_63298.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Cisco IOS XR Software Fragmented Packets Processing Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105081");
  script_bugtraq_id(63298);
  script_cve_id("CVE-2013-5549");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11867 $");

  script_name("Cisco IOS XR Software Fragmented Packets Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63298");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131023-iosxr");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to cause a denial-of-service condition.");

  script_tag(name:"vuldetect", value:"Check the IOS XR Version");

  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug ID CSCuh30380.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco IOS XR Software is prone to a denial-of-service vulnerability.");
  script_tag(name:"affected", value:"Cisco IOS XR 3.3.0 through versions 4.2.0 are vulnerable. Customers
that are running version 4.2.1 or later of Cisco IOS XR Software, or that have previously installed the
Software Maintenance Upgrades (SMU) for Cisco bug ID CSCtz62593 are not affected by this vulnerability.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-04 10:43:54 +0200 (Thu, 04 Sep 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_detect_snmp.nasl");
  script_mandatory_keys("cisco/ios_xr/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

get_app_version( cpe:CPE );

if ( ! ver = get_kb_item( "cisco/ios_xr/version" ) ) exit( 0 );

if( version_in_range(version:ver, test_version:'3.3.0', test_version2:'4.2.0' ) )
{
  report = 'Cisco Bug ID:      CSCuh30380\nInstalled Version: ' + ver;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


