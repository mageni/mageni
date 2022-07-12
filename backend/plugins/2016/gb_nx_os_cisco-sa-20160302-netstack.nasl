###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_cisco-sa-20160302-netstack.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco NX-OS Software TCP Netstack Denial of Service Vulnerability
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

CPE = 'cpe:/o:cisco:nx-os';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105645");
  script_cve_id("CVE-2015-0718");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco NX-OS Software TCP Netstack Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-netstack");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-04 14:16:24 +0200 (Wed, 04 May 2016)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending a specific TCP packet to an affected device on a TCP session that is already in a TIME_WAIT state. An exploit could allow the attacker to cause a reload of the TCP stack on the affected device, resulting in a DoS condition.
This vulnerability can be exploited using either IPv4 or IPv6 packets. The vulnerability can be triggered by a crafted sequence of TCP packets destined for TCP ports listening on the device. The packets may use the IPv4 or IPv6 unicast address of any interface configured on the device.
This vulnerability can be triggered only by traffic destined to an affected device and cannot be exploited using traffic that transits an affected device.");

  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"The vulnerability is due to improper processing of certain TCP packets in the closing sequence of a TCP session while the affected device is in a TIME_WAIT state.");
  script_tag(name:"solution", value:"See the vendor advisory for a solution");
  script_tag(name:"summary", value:"A vulnerability in the TCP stack of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )  exit( 0 );
if( ! nx_ver = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if( nx_model =~ "^3[0-9]+" )
{
  affected = make_list("5.0(3)U1(1)",
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
                       "6.0(2)U1(1)",
                       "6.0(2)U1(1a)",
                       "6.0(2)U1(2)",
                       "6.0(2)U1(3)",
                       "6.0(2)U1(4)",
                       "6.0(2)U2(1)",
                       "6.0(2)U2(2)");
}

if( nx_model =~ "^4[0-9]+" )
{
  affected = make_list("4.1(2)E1(1)",
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
                       "4.1(2)E1(1m)");
}

if( nx_model =~ "^5[0-9]+" )
{
  affected = make_list("4.0(0)N1(1a)",
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
                       "5.0(3)N1(1c)",
                       "5.0(2)N2(1)",
                       "5.0(2)N2(1a)",
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
                       "5.2(1)N1(8a)");
}

if( nx_model =~ "^6[0-9]+" )
{
  affected = make_list("6.0(2)N1(2)",
                       "6.0(2)N1(2a)",
                       "6.0(2)N2(1)",
                       "6.0(2)N2(1b)",
                       "6.0(2)N2(2)",
                       "6.0(2)N2(3)",
                       "6.0(2)N2(4)",
                       "6.0(2)N2(5)",
                       "6.0(2)N2(5a)",
                       "6.0(2)N2(6)");
}

if( nx_model =~ "^7[0-9]+" )
{
  affected = make_list("4.1.(2)",
                       "4.1.(3)",
                       "4.1.(4)",
                       "4.1.(5)",
                       "4.2.(2a)",
                       "4.2(3)",
                       "4.2(4)",
                       "4.2(6)",
                       "4.2(8)",
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
                       "6.0(1)",
                       "6.0(2)",
                       "6.0(3)",
                       "6.0(4)",
                       "6.1(1)",
                       "6.1(2)",
                       "6.1(3)");
}

if( '1000V' >< nx_model )
{
  affected = make_list("4.0(4)SV1(1)",
                       "4.0(4)SV1(2)",
                       "4.0(4)SV1(3)",
                       "4.0(4)SV1(3a)",
                       "4.0(4)SV1(3b)",
                       "4.0(4)SV1(3c)",
                       "4.0(4)SV1(3d)");
}

if( affected )
{
  foreach af ( affected )
  {
    if( nx_ver == af )
    {
      report = report_fixed_ver(  installed_version:nx_ver, fixed_version:"See advisory" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

