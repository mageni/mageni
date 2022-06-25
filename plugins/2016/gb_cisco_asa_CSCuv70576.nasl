###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCuv70576.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Adaptive Security Appliance VPN Memory Block Exhaustion Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106081");
  script_cve_id("CVE-2016-1379");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_version("$Revision: 12431 $");

  script_name("Cisco Adaptive Security Appliance VPN Memory Block Exhaustion Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160517-asa-vpn");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the IPsec code of Cisco Adaptive Security Appliance
(ASA) Software could allow an authenticated, remote attacker to cause the depletion of a memory block, which
may cause the system to stop forwarding traffic and result in a denial of service (DoS) condition.

The vulnerability is due to an error in the implementation of ICMP error handling for IPsec packets. An
attacker could exploit this vulnerability by sending crafted packets through an established LAN-to-LAN or
Remote Access VPN tunnel. A successful exploit could allow the attacker to deplete available memory and cause
system instability or cause the system to stop forwarding traffic.

Cisco has released software updates that address this vulnerability. There are no workarounds that address
this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-19 11:12:00 +0700 (Thu, 19 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
check_vers = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

affected = make_list(
		'9.0.1',
		'9.0.2',
		'9.0.2.10',
		'9.0.3',
		'9.0.3.6',
		'9.0.3.8',
		'9.0.4',
		'9.0.4.1',
		'9.0.4.5',
		'9.0.4.7',
		'9.0.4.17',
		'9.0.4.20',
		'9.0.4.24',
		'9.0.4.26',
		'9.0.4.29',
		'9.0.4.33',
		'9.0.4.35',
		'9.0.4.37',
		'9.1.1',
		'9.1.1.4',
		'9.1.2',
		'9.1.2.8',
		'9.1.3',
		'9.1.3.2',
		'9.1.4',
		'9.1.4.5',
		'9.1.5',
		'9.1.5.10',
		'9.1.5.12',
		'9.1.5.15',
		'9.1.5.21',
		'9.1.6',
		'9.1.6.1',
		'9.1.6.4',
		'9.1.6.6',
		'9.1.6.8',
		'9.2.1',
		'9.2.2',
		'9.2.2.4',
		'9.2.2.7',
		'9.2.2.8',
		'9.2.3',
		'9.2.3.3',
		'9.2.3.4',
		'9.2.0.0',
		'9.2.0.104',
		'9.2.3.1',
		'9.2.4',
		'9.3.1',
		'9.3.1.1',
		'9.3.2',
		'9.3.2.2',
		'9.3.3',
		'9.3.3.1',
		'9.3.3.2',
		'9.3.3.5',
		'9.3.1.105',
		'9.3.2.100',
		'9.3.3.6',
		'9.3.2.243',
		'9.3.1.50',
		'9.4.1',
		'9.4.0.115',
		'9.4.1.1',
		'9.4.1.2',
		'9.4.1.3',
		'9.4.1.5',
		'9.5.1' );

foreach af ( affected )
{
  if( check_vers == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

