###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20160525-ipv6.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105734");
  script_cve_id("CVE-2016-1409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12338 $");

  script_name("Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability (NX OS)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160525-ipv6");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the IP Version 6 (IPv6) packet processing functions of Cisco IOS XR Software,
  Cisco IOS XE Software, and Cisco NX-OS Software could allow an unauthenticated, remote attacker to
  cause an affected device to stop processing IPv6 traffic, leading to a denial of service (DoS)
  condition on the device.

  The vulnerability is due to insufficient processing logic for crafted IPv6 packets that are sent
  to an affected device. An attacker could exploit this vulnerability by sending crafted IPv6
  Neighbor Discovery packets to an affected device for processing. A successful exploit could allow
  the attacker to cause the device to stop processing IPv6 traffic, leading to a DoS condition on
  the device.

  Cisco will release software updates that address this vulnerability. There are no workarounds that
  address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-30 11:03:00 +0200 (Mon, 30 May 2016)");
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

if( "1000V" >< nx_model )
{
  affected = make_list(
			"4.0(4)SV1(1)",
			"4.0(4)SV1(2)",
			"4.0(4)SV1(3)",
			"4.0(4)SV1(3a)",
			"4.0(4)SV1(3b)",
			"4.0(4)SV1(3c)",
			"4.0(4)SV1(3d)",
			"4.2(1)SV1(4)",
			"4.2(1)SV1(4a)",
			"4.2(1)SV1(4b)",
			"4.2(1)SV1(5.1)",
			"4.2(1)SV1(5.1a)",
			"4.2(1)SV1(5.2)",
			"4.2(1)SV1(5.2b)",
			"4.2(1)SV2(1.1)",
			"4.2(1)SV2(1.1a)",
			"4.2(1)SV2(2.1)",
			"4.2(1)SV2(2.1a)",
			"5.2(1)SV3(1.4)",
			"7.3(0)ZN(0.7)",
			"7.3(0)ZN(0.81)",
			"7.3(0)ZN(0.9)"
		);
}

if( nx_model =~ "^3[0-9]+" )
{
  affected = make_list(
			"5.0(3)U1(1)",
			"5.0(3)U1(1a)",
			"5.0(3)U1(1b)",
			"5.0(3)U1(1d)",
			"5.0(3)U1(2)",
			"5.0(3)U1(2a)",
			"5.0(3)U2(1)",
			"5.0(3)U2(2)",
			"5.0(3)U2(2a)",
			"5.0(3)U2(2b)",
			"5.0(3)U2(2c)",
			"5.0(3)U2(2d)",
			"5.0(3)U3(1)",
			"5.0(3)U3(2)",
			"5.0(3)U3(2a)",
			"5.0(3)U3(2b)",
			"5.0(3)U4(1)",
			"5.0(3)U5(1)",
			"5.0(3)U5(1a)",
			"5.0(3)U5(1b)",
			"5.0(3)U5(1c)",
			"5.0(3)U5(1d)",
			"5.0(3)U5(1e)",
			"5.0(3)U5(1f)",
			"5.0(3)U5(1g)",
			"5.0(3)U5(1h)",
			"6.0(2)A6(1)",
			"6.0(2)A6(2)",
			"6.0(2)A6(3)",
			"6.0(2)A6(4)",
			"6.0(2)A6(5)",
			"6.0(2)A7(1)",
			"6.0(2)U1(1)",
			"6.0(2)U1(1a)",
			"6.0(2)U1(2)",
			"6.0(2)U1(3)",
			"6.0(2)U1(4)",
			"6.0(2)U2(1)",
			"6.0(2)U2(2)",
			"6.0(2)U2(3)",
			"6.0(2)U2(4)",
			"6.0(2)U2(5)",
			"6.0(2)U2(6)",
			"6.0(2)U3(1)",
			"6.0(2)U3(2)",
			"6.0(2)U3(3)",
			"6.0(2)U3(4)",
			"6.0(2)U3(5)",
			"6.0(2)U4(1)",
			"6.0(2)U4(2)",
			"6.0(2)U4(3)",
			"6.0(2)U5(1)",
			"6.0(2)U5(1.41)",
			"6.0(2)U6(0.46)",
			"6.0(2)U6(1)",
			"6.0(2)U6(2)",
			"6.0(2)U6(3)",
			"6.0(2)U6(4)",
			"6.0(2)U6(5)",
			"7.0(3)I2(0.373)",
			"7.2(0)ZN(99.67)",
			"7.2(0)ZZ(99.1)",
			"7.3(0)ZD(0.47)",
			"7.3(0)ZN(0.81)",
			"7.3(0)ZN(0.83)"
		);
}

if( nx_model =~ "^4[0-9]+" )
{
  affected = make_list(
			"4.1(2)E1(1)",
			"4.1(2)E1(1b)",
			"4.1(2)E1(1c)",
			"4.1(2)E1(1d)",
			"4.1(2)E1(1e)",
			"4.1(2)E1(1f)",
			"4.1(2)E1(1g)",
			"4.1(2)E1(1h)",
			"4.1(2)E1(1i)",
			"4.1(2)E1(1j)",
			"4.1(2)E1(1k)",
			"4.1(2)E1(1m)",
			"4.1(2)E1(1n)",
			"4.1(2)E1(1o)"
		);
}

if( nx_model =~ "^5[0-9]+" )
{
  affected = make_list(
			"4.0(0)N1(1a)",
			"4.0(0)N1(2)",
			"4.0(0)N1(2a)",
			"4.0(1a)N1(1)",
			"4.0(1a)N1(1a)",
			"4.0(1a)N2(1)",
			"4.0(1a)N2(1a)",
			"4.1(3)N1(1)",
			"4.1(3)N1(1a)",
			"4.1(3)N2(1)",
			"4.1(3)N2(1a)",
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
			"5.2(1)N1(8a)",
			"5.2(9)N1(1)",
			"6.0(2)N1(1)",
			"6.0(2)N1(2)",
			"6.0(2)N1(2a)",
			"6.0(2)N2(1)",
			"6.0(2)N2(1b)",
			"6.0(2)N2(2)",
			"6.0(2)N2(3)",
			"6.0(2)N2(4)",
			"6.0(2)N2(5)",
			"7.0(0)N1(1)",
			"7.0(1)N1(1)",
			"7.0(1)N1(3)",
			"7.0(2)N1(1)",
			"7.0(3)N1(1)",
			"7.0(4)N1(1)",
			"7.0(6)N1(1)",
			"7.1(1)N1(1)",
			"7.2(0)D1(0.437)",
			"7.2(0)ZZ(99.1)",
			"7.3(0.2)"
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
			"6.0(2)N2(7)",
			"7.0(0)N1(1)",
			"7.0(1)N1(1)",
			"7.0(2)N1(1)",
			"7.0(3)N1(1)",
			"7.0(4)N1(1)",
			"7.0(5)N1(1)",
			"7.0(5)N1(1a)",
			"7.0(6)N1(1)",
			"7.0(7)N1(1)",
			"7.1(0)N1(1a)",
			"7.1(0)N1(1b)",
			"7.1(1)N1(1)",
			"7.1(2)N1(1)",
			"7.1(3)N1(1)",
			"7.2(0)N1(1)",
			"7.2(1)N1(1)"
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
			"1.0(1.110a)",
			"1.0(1e)",
			"1.0(2j)",
			"1.1(0.825a)",
			"1.1(1g)",
			"11.0(1b)",
			"11.0(1c)",
			"11.0(1d)",
			"11.0(1e)",
			"11.0(2j)",
			"11.0(2m)",
			"11.0(3f)",
			"11.0(3i)",
			"11.0(3k)",
			"11.0(3n)",
			"11.0(4h)",
			"11.0(4o)",
			"11.1(1c)",
			"11.1(1j)",
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
			"7.0(3)",
			"7.0(3)I1(1)",
			"7.0(3)I1(1a)",
			"7.0(3)I1(1b)",
			"7.0(3)I1(2)",
			"7.2(0)ZZ(99.3)",
			"7.3(0)ZD(0.61)",
			"7.3(0)ZN(0.81)",
			"7.3(0)ZN(0.9)"
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

