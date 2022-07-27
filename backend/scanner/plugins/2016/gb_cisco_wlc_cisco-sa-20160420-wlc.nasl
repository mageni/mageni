###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_cisco-sa-20160420-wlc.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco Wireless LAN Controller Management Interface Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105742");
  script_cve_id("CVE-2016-1362");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-01 11:56:51 +0200 (Wed, 01 Jun 2016)");
  script_name("Cisco Wireless LAN Controller Management Interface Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-wlc");

  script_tag(name:"summary", value:"A vulnerability in the web-based management interface of Cisco Wireless LAN Controller (WLC) devices running Cisco AireOS Softwar");
  script_tag(name:"impact", value:"The vulnerability is due to the presence of unsupported URLs in the web-based device management interface provided by the affected software. An attacker could exploit this vulnerability by attempting to access a URL that is not generally accessible from and supported by the management interface. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"affected", value:"Releases 4.1 through 7.4.120.0
All 7.5 releases
Release 7.6.100.0");

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

if( vers =~ "^[456]\." ) fix = '8.0.132.0';

if( vers =~ "^7\.[01235]" ) fix = '8.0.132.0';

if( vers =~ "^7\.4" )
  if( version_is_less( version:vers, test_version:"7.4.130.0" ) ) fix = '7.4.130(MD)';

if( vers =~ "^7\.6" )
  if( version_is_less( version:vers, test_version:"7.6.120.0" ) ) fix = '7.6.120.0';

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

