###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20161005-bgp.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco NX-OS Border Gateway Protocol Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.107097");
  script_cve_id("CVE-2016-1454");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco NX-OS Border Gateway Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-bgp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Border Gateway Protocol (BGP) implementation of
Cisco NX-OS System Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
condition due to the device unexpectedly reloading.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation of the BGP update
messages. An attacker could exploit this vulnerability by sending a crafted BGP update message to the targeted
device. To exploit this vulnerability, an attacker must be able to send the malicious packets over a TCP
connection that appears to come from a trusted BGP peer, or inject malformed messages into the victim's BGP
network.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the switch to reload
unexpectedly.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 09:39:36 +0700 (Thu, 06 Oct 2016)");
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
			"5.2(1)SV3(1.1)",
			"5.2(1)SV3(1.10)",
			"5.2(1)SV3(1.3)",
			"5.2(1)SV3(1.4)",
			"5.2(1)SV3(1.5a)",
			"5.2(1)SV3(1.5b)",
			"5.2(1)SV3(1.6)"
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
			"6.0(2)A6(6)",
			"6.0(2)A6(7)",
			"6.0(2)A6(8)",
			"6.0(2)A7(1)",
			"6.0(2)A7(2)",
			"6.0(2)A7(2a)",
			"6.0(2)A8(2)",
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
			"6.0(2)U5(2)",
			"6.0(2)U5(3)",
			"6.0(2)U5(4)",
			"6.0(2)U6(0.46)",
			"6.0(2)U6(1)",
			"6.0(2)U6(2)",
			"6.0(2)U6(3)",
			"6.0(2)U6(4)",
			"6.0(2)U6(5)",
			"6.0(2)U6(6)",
			"6.0(2)U6(7)",
			"6.0(2)U6(8)",
			"7.0(3)I2(0.373)"
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
			"6.0(2)N2(5a)",
			"6.0(2)N2(6)",
			"6.0(2)N2(7)",
			"7.0(0)N1(1)",
			"7.0(1)N1(1)",
			"7.0(2)N1(1)",
			"7.0(3)N1(1)",
			"7.0(5)N1(1)",
			"7.0(5)N1(1a)",
			"7.0(6)N1(1)",
			"7.0(7)N1(1)",
			"7.0(8)N1(1)",
			"7.1(1)N1(1)",
			"7.1(2)N1(1)",
			"7.1(3)N1(1)",
			"7.1(3)N1(2)",
			"7.1(4)N1(1)",
			"7.2(0)N1(1)",
			"7.2(1)N1(1)"
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
			"11.1(1o)",
			"11.1(1r)",
			"11.1(1s)",
			"11.1(2h)",
			"11.1(2i)",
			"11.1(3f)",
			"11.1(4e)",
			"11.1(4f)",
			"11.1(4g)",
			"11.1(4i)",
			"11.1(4l)",
			"11.1(4m)",
			"11.2(1m)",
			"11.2(2g)",
			"11.2(2h)",
			"11.2(2i)",
			"11.2(3c)",
			"11.2(3e)",
			"11.2(3h)",
			"11.3(1i)",
			"11.3(2f)",
			"11.3(2h)",
			"11.3(2i)",
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
			"7.0(3)I1(2)"
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

