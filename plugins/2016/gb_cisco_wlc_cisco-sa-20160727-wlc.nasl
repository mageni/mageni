###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_cisco-sa-20160727-wlc.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Cisco Wireless LAN Controller Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105837");
  script_cve_id("CVE-2016-1460");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11961 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-29 18:17:42 +0200 (Fri, 29 Jul 2016)");
  script_name("Cisco Wireless LAN Controller Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-wlc");

  script_tag(name:"summary", value:"A vulnerability in wireless frame management service of the Cisco Wireless LAN Controller (WLC) could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on the affected device.");
  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending crafted wireless management frames to the device.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"affected", value:"Cisco Wireless LAN Controller (WLC) versions 7.4(121.0) and 8.0(0.30220.385) are affected.");

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

if( vers =~ "^7\.4" )
  if( version_is_less( version:vers, test_version:"7.4.140.1" ) ) fix = '7.4(140.1)';


if( vers =~ "^8\.0" )
  if( version_is_less( version:vers, test_version:"8.0.100.0" ) ) fix = '8.0(100.0)';


if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

