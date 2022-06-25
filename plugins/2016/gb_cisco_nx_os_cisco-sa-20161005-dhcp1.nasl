###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20161005-dhcp1.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco NX-OS Software Crafted DHCPv4 Packet Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106331");
  script_cve_id("CVE-2015-6392");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12149 $");

  script_name("Cisco NX-OS Software Crafted DHCPv4 Packet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-dhcp1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the implementation of the DHCPv4 relay agent and smart
relay agent in Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service
(DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of crafted DHCPv4 offer
packets. An attacker could exploit this vulnerability by sending crafted DHCPv4 offer packets to an affected
device. This vulnerability can be exploited using IPv4 packets only. The vulnerability can be triggered by
crafted DHCP packets processed by a DHCP relay agent or smart relay agent listening on the device using the IPv4
broadcast address or the IPv4 unicast address of any interface configured on a device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the DHCP process or device to
crash.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 10:37:59 +0700 (Thu, 06 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) ) exit( 0 );

if( nx_model =~ "^5[0-9]+" )
{
  affected = make_list(
			"4.2(1)N1(1)",
			"4.2(1)N2(1)",
			"4.2(1)N2(1a)",
			"5.0(2)N1(1)",
			"5.0(2)N2(1)",
			"5.0(2)N2(1a)",
			"5.0(3)N1(1c)",
			"5.0(3)N2(1)",
			"5.0(3)N2(2)",
			"5.0(3)N2(2a)",
			"5.0(3)N2(2b)",
			"5.1(3)N1(1)",
			"5.1(3)N1(1a)",
			"5.1(3)N2(1)",
			"5.1(3)N2(1a)",
			"5.1(3)N2(1b)",
			"5.1(3)N2(1c)",
			"5.2(1)N1(1)",
			"5.2(1)N1(1a)",
			"5.2(1)N1(1b)",
			"5.2(1)N1(2)",
			"5.2(1)N1(2a)",
			"5.2(1)N1(3)",
			"5.2(1)N1(4)",
			"5.2(1)N1(5)",
			"5.2(1)N1(6)",
			"5.2(1)N1(7)",
			"5.2(1)N1(8)",
			"5.2(1)N1(8a)"
		);
}

if( nx_model =~ "^6[0-9]+" )
{
  affected = make_list(
			"6.0(2)N1(2)",
			"6.0(2)N1(2a)",
			"6.0(2)N2(1)",
			"6.0(2)N2(1b)",
			"6.0(2)N2(2)",
			"6.0(2)N2(3)",
			"6.0(2)N2(4)",
			"6.0(2)N2(5)",
			"6.0(2)N2(5a)",
			"6.0(2)N2(6)",
			"7.0(0)N1(1)",
			"7.0(1)N1(1)",
			"7.0(2)N1(1)",
			"7.0(3)N1(1)",
			"7.0(4)N1(1)",
			"7.0(5)N1(1)",
			"7.0(5)N1(1a)",
			"7.1(0)N1(1a)",
			"7.1(0)N1(1b)"
		);
}

if( nx_model =~ "^7[0-9]+" )
{
  affected = make_list(
			"4.1.(2)",
			"4.1.(3)",
			"4.1.(4)",
			"4.1.(5)",
			"4.2(3)",
			"4.2(4)",
			"4.2(6)",
			"4.2(8)",
			"4.2.(2a)",
			"5.0(2a)",
			"5.0(3)",
			"5.0(5)",
			"5.1(1)",
			"5.1(1a)",
			"5.1(3)",
			"5.1(4)",
			"5.1(5)",
			"5.1(6)",
			"5.2(1)",
			"5.2(3a)",
			"5.2(4)",
			"5.2(5)",
			"5.2(7)",
			"5.2(9)",
			"6.0(1)",
			"6.0(2)",
			"6.0(3)",
			"6.0(4)",
			"6.1(1)",
			"6.1(2)",
			"6.1(3)",
			"6.1(4)",
			"6.1(4a)",
			"6.1(5)",
			"6.2(10)",
			"6.2(12)",
			"6.2(14)S1",
			"6.2(2)",
			"6.2(2a)",
			"6.2(6)",
			"6.2(6b)",
			"6.2(8)",
			"6.2(8a)",
			"6.2(8b)",
			"7.2(0)N1(0.1)"
		);
}

if( nx_model =~ "^N9K" )
{
  affected = make_list(
			"6.1(2)I2(1)",
			"6.1(2)I2(2)",
			"6.1(2)I2(2a)",
			"6.1(2)I2(2b)",
			"6.1(2)I2(3)",
			"6.1(2)I3(1)",
			"6.1(2)I3(2)",
			"6.1(2)I3(3)",
			"6.1(2)I3(3.78)",
			"6.1(2)I3(4)",
			"7.0(3)"
		);
}


foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

