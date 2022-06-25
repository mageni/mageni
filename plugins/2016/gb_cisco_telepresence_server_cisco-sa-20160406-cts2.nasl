###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_server_cisco-sa-20160406-cts2.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco TelePresence Server Malformed STUN Packet Processing Denial of Service Vulnerability
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

CPE = "cpe:/a:cisco:telepresence_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105609");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2015-6312");
  script_name("Cisco TelePresence Server Malformed STUN Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-cts2");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by submitting malformed STUN packets to the device. If successful, the attacker could force the device to reload and drop all calls in the process.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to a failure to properly process malformed Session Traversal Utilities for NAT (STUN) packets.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"A vulnerability in Cisco TelePresence Server devices running software version 3.1 could allow an unauthenticated, remote attacker to reload the device.");

  script_tag(name:"affected", value:"The following Cisco TelePresence Server devices running Cisco TelePresence Server software version 3.1 are vulnerable:
Cisco TelePresence Server 7010
Cisco TelePresence Server Mobility Services Engine (MSE) 8710
Cisco TelePresence Server on Multiparty Media 310
Cisco TelePresence Server on Multiparty Media 320
Cisco TelePresence Server on Virtual Machine (VM)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 15:50:01 +0200 (Mon, 18 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_telepresence_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cisco_telepresence_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! vers =  get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers !~ "^3\.1" ) exit( 99 );

if( ! model = get_kb_item( "cisco_telepresence_server/model" ) ) exit( 0 );

if( model !~ '^7010$' && model !~ '^8710$' && model !~ 'Media 3(1|2)0' && model != "VM" ) exit( 99 );

fix = '4.2.4.18';
report_fix = '4.2(4.18)';
report_vers = vers;

vers = str_replace( string:vers, find:"(", replace:"." );
vers = str_replace( string:vers, find:")", replace:"" );

if( version_is_less( version:vers, test_version: fix ) )
{
    report = 'Installed version: ' + report_vers + '\n' +
             'Fixed version:     ' + report_fix  + '\n' +
             'Model:             ' + model       + '\n';

    security_message( port:port, data:report );
    exit( 0 );
}

exit( 99 );

