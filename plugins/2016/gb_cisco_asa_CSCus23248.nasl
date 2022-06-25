###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCus23248.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Adaptive Security Appliance Software DHCPv6 Relay Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106072");
  script_cve_id("CVE-2016-1367");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12431 $");

  script_name("Cisco Adaptive Security Appliance Software DHCPv6 Relay Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-asa-dhcpv6");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the DHCPv6 relay feature of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause an affected device to reload.

The vulnerability is due to insufficient validation of DHCPv6 packets. An attacker could exploit this vulnerability by sending crafted DHCPv6 packets to an affected device, resulting in a denial of service (DoS) condition.

This vulnerability affects systems configured in routed firewall mode and in single or multiple context mode. Cisco ASA Software is affected by this vulnerability only if the software is configured with the DHCPv6 relay feature. The vulnerability is triggered only by IPv6 traffic.

This vulnerability affects Cisco ASA Software release 9.4.1 only.

Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-12 12:19:00 +0700 (Thu, 12 May 2016)");
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
		'9.4.1' );

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

