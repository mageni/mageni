###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_CSCuw10610.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Wireless LAN Controller Client Disconnection Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105416");
  script_cve_id("CVE-2015-6341");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-21 14:29:20 +0200 (Wed, 21 Oct 2015)");
  script_name("Cisco Wireless LAN Controller Client Disconnection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151016-wlc");

  script_tag(name:"summary", value:"A vulnerability in the Web Management GUI of the Cisco Wireless LAN Controller (WLC) could allow an unauthenticated, remote attacker to trigger client disconnection.");
  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by connecting to the IP address of the Cisco WLC and triggering client disconnections. The attacker must reach the Cisco WLC management IP address on port 80 or port 443 via its wired interface.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to a lack of access control to the Cisco WLC Web Management GUI.");
  script_tag(name:"solution", value:"See vendor advisory for a solution");
  script_tag(name:"affected", value:"Cisco WLC Software versions 7.4(140.0) and 8.0(120.0) are vulnerable.");

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

CPE = 'cpe:/o:cisco:wireless_lan_controller_software';

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( vers == "7.4.140.0" || vers == "8.0.120.0" )
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     See vendor advisory\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

