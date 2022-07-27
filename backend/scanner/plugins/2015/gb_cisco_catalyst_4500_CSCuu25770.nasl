###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_catalyst_4500_CSCuu25770.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Catalyst 4500 IOS XE Cisco Discovery Protocol Packet Processing Denial of Service Vulnerability
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

CPE = "cpe:/h:cisco:catalyst_4500";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105381");
  script_cve_id("CVE-2015-6294");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Catalyst 4500 IOS XE Cisco Discovery Protocol Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=41006");

  script_tag(name:"impact", value:"An unauthenticated, adjacent attacker could exploit the vulnerability to cause the Cisco Discovery Protocol packet process on the software to stop functioning properly, resulting in a DoS condition on the affected device.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of valid crafted Cisco Discovery Protocol packets. An attacker could exploit this vulnerability by sending crafted Cisco Discovery
Protocol packets to be processed by an affected device. An exploit could allow the attacker to cause the software to stop functioning properly, resulting in a DoS condition on the affected device.");

  script_tag(name:"solution", value:"Updates are available. See vendor advisory for more information.");
  script_tag(name:"summary", value:"Cisco IOS XE contains a vulnerability that could allow an unauthenticated, adjacent attacker to cause a denial of service condition. Updates are available.");
  script_tag(name:"affected", value:"Cisco IOS XE Software Releases 3.6(2)E and prior and Cisco IOS Software Releases 15.2(3)E and prior were vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-21 15:09:03 +0200 (Mon, 21 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_catalyst_4500_detect.nasl");
  script_mandatory_keys("cisco_catalyst_4500/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( get_kb_item( "cisco_catalyst_4500/IOS-XE" ) )
{
  report_fix = '3.6(2)E';
  fix = '03.06.02.E';

  if( version_is_less( version:vers, test_version:fix ) )
  {
    VULN = TRUE;
  }
}

if( vers == "15.2(2)E" || vers == "15.2(2)E1" || vers == "15.2(2)E2" || vers == "15.2(3)E" )
{
  VULN = TRUE;
}

if( VULN  )
{
  report = 'Installed version: ' + vers + '\n';

  if( report_fix )
    report += 'Fixed version:     ' + report_fix + '\n';
  else
    report += 'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

