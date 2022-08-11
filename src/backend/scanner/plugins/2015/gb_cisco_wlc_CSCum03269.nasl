###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_CSCum03269.nasl 14184 2019-03-14 13:29:04Z cfischer $
#
# Cisco Wireless LAN Controller Wireless Web Authentication Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105385");
  script_cve_id("CVE-2015-0723");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 14184 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-23 13:59:48 +0200 (Wed, 23 Sep 2015)");
  script_name("Cisco Wireless LAN Controller Wireless Web Authentication Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=38749");

  script_tag(name:"summary", value:"Cisco Wireless LAN Controller contains a vulnerability that could allow an
  unauthenticated, adjacent attacker to cause a denial of service condition. Updates are available.");
  script_tag(name:"impact", value:"An unauthenticated, adjacent attacker could exploit this vulnerability
  to cause a process on an affected device to crash, resulting in a DoS condition.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists due to improper input sanitization of a certain value
  that is supplied by a user prior to successfully authenticating to an affected device. An attacker could exploit this
  vulnerability by sending a request designed to trigger the vulnerability and cause a process crash that will trigger a
  restart of the device, resulting in a DoS condition.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"affected", value:"Cisco WLC versions 7.5.x or versions prior to 7.6.120 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/o:cisco:wireless_lan_controller_software';

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"7.5", test_version2:"7.6.120.0" ) )
{
  if( version_is_less( version:vers, test_version:"7.6.120.0" ) )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     7.6(120.1)\n';
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );