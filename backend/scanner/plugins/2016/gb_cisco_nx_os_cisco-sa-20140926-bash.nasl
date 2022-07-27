###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20140926-bash.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# GNU Bash Environment Variable Command Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105693");
  script_cve_id("CVE-2014-6271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11961 $");

  script_name("Cisco NX-OS: GNU Bash Environment Variable Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35836");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35880");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35845");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35879");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35860");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35861");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35816");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"On September 24, 2014, a vulnerability in the Bash shell was publicly announced. The vulnerability
  is related to the way in which shell functions are passed though environment variables. The
  vulnerability may allow an attacker to inject commands into a Bash shell, depending on how the shell
  is invoked. The Bash shell may be invoked by a number of processes including, but not limited to,
  telnet, SSH, DHCP, and scripts hosted on web servers.

  All versions of GNU Bash starting with version 1.14 are affected by this vulnerability and the
  specific impact is determined by the characteristics of the process using the Bash shell. In the
  worst case, an unauthenticated remote attacker would be able to execute commands on an affected
  server. However, in most cases involving Cisco products, authentication is required before
  exploitation could be attempted.

  A number of Cisco products ship with or use an affected version of the Bash shell. The Bash shell is
  a third-party software component that is part of the GNU software project and used by a number of
  software vendors. As of this version of the Security Advisory, there have been a number of
  vulnerabilities recently discovered in the Bash shell, and the investigation is ongoing. For
  vulnerable products, Cisco has included information on the product versions that will contain the
  fixed software, and the date these versions are expected to be published on the cisco.com download
  page. This advisory will be updated as additional information becomes available. Cisco may release
  free software updates that address this vulnerability if a product is determined to be affected by
  this vulnerability. This advisory is available at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-12 15:45:58 +0200 (Thu, 12 May 2016)");
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
			"4.2(1)SV2(2.1a)"
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
			"6.0(2)U1(1)",
			"6.0(2)U1(1a)",
			"6.0(2)U1(2)",
			"6.0(2)U1(3)",
			"6.0(2)U4(1)"
		);
}

if( nx_model =~ "^4[0-9]+" )
{
  affected = make_list(
			"4.1(2)E1(1)",
			"4.1(2)E1(1b)",
			"4.1(2)E1(1d)",
			"4.1(2)E1(1e)",
			"4.1(2)E1(1f)",
			"4.1(2)E1(1g)",
			"4.1(2)E1(1h)",
			"4.1(2)E1(1i)",
			"4.1(2)E1(1j)"
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
			"7.0(2)N1(1)",
			"7.0(3)N1(1)"
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
			"7.0(0)N1(1)",
			"7.0(1)N1(1)",
			"7.0(2)N1(1)",
			"7.0(3)N1(1)"
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
			"6.2(2)",
			"6.2(2a)",
			"6.2(6)"
		);
}

if( nx_model =~ "^N9K" )
{
  affected = make_list(
			"11.0(1b)",
			"11.0(1c)",
			"6.1(2)I2(1)",
			"6.1(2)I2(2)",
			"6.1(2)I2(2a)",
			"6.1(2)I2(2b)",
			"6.1(2)I2(3)"
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

