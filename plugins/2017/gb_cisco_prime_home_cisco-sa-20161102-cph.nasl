###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_prime_home_cisco-sa-20161102-cph.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Prime Home Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:prime_home";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140149");
  script_cve_id("CVE-2016-6452");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Prime Home Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-cph");

  script_tag(name:"impact", value:"The vulnerability is due to a processing error in the role-based access control (RBAC) of URLs. An attacker could exploit this vulnerability by sending a crafted HTTP request to a particular URL. An exploit could allow the attacker to obtain a valid session identifier for an arbitrary user, which would allow the attacker to perform any actions in Cisco Prime Home for which that user is authorized-including users with administrator privileges.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to 5.1.1.7/5.2.2.3");
  script_tag(name:"summary", value:"A vulnerability in the web-based graphical user interface (GUI) of Cisco Prime Home could allow an unauthenticated, remote attacker to bypass authentication. The attacker could be granted full administrator privileges.");
  script_tag(name:"affected", value:"Cisco Prime Home versions 5.1.1.6 and earlier and 5.2.2.2 and earlier have been confirmed to be vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 16:06:02 +0100 (Thu, 02 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_prime_home_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.1.1.7" ) ) fix = '5.1.1.7';
if( version_in_range( version:vers, test_version:"5.1.2", test_version2:"5.2.2.2" ) ) fix = '5.2.2.3';

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

