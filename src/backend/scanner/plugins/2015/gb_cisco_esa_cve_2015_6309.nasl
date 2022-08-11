###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_esa_cve_2015_6309.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Email Security Appliance Max Files Denial of Service Vulnerability
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

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105402");
  script_cve_id("CVE-2015-6309");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Email Security Appliance Format String Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=41241");

  script_tag(name:"impact", value:"An authenticated, remote attacker could exploit this vulnerability to cause an affected device to reload unexpectedly, resulting in a DoS condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to failure to release file descriptors when the requested file action is completed. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to cause a DoS condition due to the affected device failing to release file descriptors. When all file descriptors are in use, the device can reload unexpectedly.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Cisco Email Security Appliance contains a vulnerability that could allow an authenticated, remote attacker to cause a denial of service condition.");
  script_tag(name:"affected", value:"Cisco Email Security Appliance 8.5.6-106/9.6.0-042");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-14 14:43:01 +0200 (Wed, 14 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( "9.6.0-042","8.5.6-106" );

foreach af ( affected )
{
  if( vers == af )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     See vendor advisory';
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

