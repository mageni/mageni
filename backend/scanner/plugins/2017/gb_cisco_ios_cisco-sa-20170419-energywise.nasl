###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20170419-energywise.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS Software EnergyWise Denial of Service Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106776");
  script_cve_id("CVE-2017-3860", "CVE-2017-3861", "CVE-2017-3862", "CVE-2017-3863");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS Software EnergyWise Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Multiple vulnerabilities in the EnergyWise module of Cisco IOS Software
could allow an unauthenticated, remote attacker to cause a buffer overflow condition or a reload of an affected
device, leading to a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"These vulnerabilities are due to improper parsing of crafted EnergyWise
packets destined to an affected device. An attacker could exploit these vulnerabilities by sending crafted
EnergyWise packets to be processed by an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a buffer overflow condition or a
reload of the affected device, leading to a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 15:30:49 +0200 (Thu, 20 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'12.2(33)SXI10',
		'12.2(33)SXI11',
		'12.2(33)SXI12',
		'12.2(33)SXI13',
		'12.2(33)SXI14',
		'12.2(33)SXI4',
		'12.2(33)SXI4a',
		'12.2(33)SXI5',
		'12.2(33)SXI6',
		'12.2(33)SXI7',
		'12.2(33)SXI8',
		'12.2(33)SXI8a',
		'12.2(33)SXI9',
		'12.2(33)SXJ',
		'12.2(33)SXJ1',
		'12.2(33)SXJ10',
		'12.2(33)SXJ2',
		'12.2(33)SXJ3',
		'12.2(33)SXJ4',
		'12.2(33)SXJ5',
		'12.2(33)SXJ6',
		'12.2(33)SXJ7',
		'12.2(33)SXJ8',
		'12.2(33)SXJ9',
		'12.2(52)EX',
		'12.2(52)EX1',
		'12.2(52)EY',
		'12.2(52)EY1',
		'12.2(52)EY1b',
		'12.2(52)EY1c',
		'12.2(52)EY2',
		'12.2(52)EY2a',
		'12.2(52)EY3',
		'12.2(52)EY3a',
		'12.2(52)EY4',
		'12.2(53)EX',
		'12.2(53)EY',
		'12.2(53)EZ',
		'12.2(53)SE',
		'12.2(53)SE1',
		'12.2(53)SE2',
		'12.2(54)SE',
		'12.2(54)SG',
		'12.2(54)SG1',
		'12.2(54)WO',
		'12.2(54)XO',
		'12.2(55)EX',
		'12.2(55)EX1',
		'12.2(55)EX2',
		'12.2(55)EX3',
		'12.2(55)EY',
		'12.2(55)EZ',
		'12.2(55)SE',
		'12.2(55)SE1',
		'12.2(55)SE10',
		'12.2(55)SE11',
		'12.2(55)SE2',
		'12.2(55)SE3',
		'12.2(55)SE4',
		'12.2(55)SE5',
		'12.2(55)SE6',
		'12.2(55)SE7',
		'12.2(55)SE8',
		'12.2(55)SE9',
		'12.2(58)EY',
		'12.2(58)EY1',
		'12.2(58)EY2',
		'12.2(58)SE',
		'12.2(58)SE1',
		'12.2(58)SE2',
		'12.2(60)EZ',
		'12.2(60)EZ1',
		'12.2(60)EZ2',
		'12.2(60)EZ3',
		'12.2(60)EZ4',
		'12.2(60)EZ5',
		'12.2(60)EZ6',
		'12.2(60)EZ7',
		'12.2(60)EZ8',
		'12.2(60)EZ9',
		'15.0(1)M10',
		'15.0(1)M2',
		'15.0(1)M3',
		'15.0(1)M4',
		'15.0(1)M5',
		'15.0(1)M6',
		'15.0(1)M7',
		'15.0(1)M8',
		'15.0(1)M9',
		'15.0(1)SE',
		'15.0(1)SE1',
		'15.0(1)SE2',
		'15.0(1)SE3',
		'15.0(1)SY1',
		'15.0(1)SY10',
		'15.0(1)SY2',
		'15.0(1)SY3',
		'15.0(1)SY4',
		'15.0(1)SY5',
		'15.0(1)SY6',
		'15.0(1)SY7',
		'15.0(1)SY7a',
		'15.0(1)SY8',
		'15.0(1)SY9',
		'15.0(1)XO',
		'15.0(1)XO1',
		'15.0(2)ED',
		'15.0(2)ED1',
		'15.0(2)EH',
		'15.0(2)EJ',
		'15.0(2)EJ1',
		'15.0(2)EK',
		'15.0(2)EK1',
		'15.0(2)EX',
		'15.0(2)EX1',
		'15.0(2)EX10',
		'15.0(2)EX2',
		'15.0(2)EX3',
		'15.0(2)EX4',
		'15.0(2)EX5',
		'15.0(2)EX8',
		'15.0(2)EZ',
		'15.0(2)SE',
		'15.0(2)SE1',
		'15.0(2)SE10',
		'15.0(2)SE2',
		'15.0(2)SE3',
		'15.0(2)SE4',
		'15.0(2)SE5',
		'15.0(2)SE6',
		'15.0(2)SE7',
		'15.0(2)SE9',
		'15.0(2)SG',
		'15.0(2)SG1',
		'15.0(2)SG2',
		'15.0(2)SG3',
		'15.0(2)SG4',
		'15.0(2)SG5',
		'15.0(2)SG6',
		'15.0(2)SG7',
		'15.0(2)SG8',
		'15.0(2)XO',
		'15.0(2a)EX5',
		'15.0(2a)SE9',
		'15.1(1)SG',
		'15.1(1)SG1',
		'15.1(1)SG2',
		'15.1(1)SY',
		'15.1(1)SY2',
		'15.1(1)SY3',
		'15.1(1)SY4',
		'15.1(1)SY5',
		'15.1(1)SY6',
		'15.1(1)T',
		'15.1(1)T1',
		'15.1(1)T2',
		'15.1(1)T3',
		'15.1(1)T4',
		'15.1(1)T5',
		'15.1(2)GC',
		'15.1(2)GC1',
		'15.1(2)GC2',
		'15.1(2)SG',
		'15.1(2)SG1',
		'15.1(2)SG2',
		'15.1(2)SG3',
		'15.1(2)SG4',
		'15.1(2)SG5',
		'15.1(2)SG6',
		'15.1(2)SG7',
		'15.1(2)SG8',
		'15.1(2)SY',
		'15.1(2)SY1',
		'15.1(2)SY10',
		'15.1(2)SY2',
		'15.1(2)SY3',
		'15.1(2)SY4',
		'15.1(2)SY4a',
		'15.1(2)SY5',
		'15.1(2)SY6',
		'15.1(2)SY7',
		'15.1(2)SY8',
		'15.1(2)T',
		'15.1(2)T0a',
		'15.1(2)T1',
		'15.1(2)T2',
		'15.1(2)T2a',
		'15.1(2)T3',
		'15.1(2)T4',
		'15.1(2)T5',
		'15.1(3)T',
		'15.1(3)T1',
		'15.1(3)T2',
		'15.1(3)T3',
		'15.1(3)T4',
		'15.1(4)GC',
		'15.1(4)GC1',
		'15.1(4)GC2',
		'15.1(4)M',
		'15.1(4)M1',
		'15.1(4)M10',
		'15.1(4)M2',
		'15.1(4)M3',
		'15.1(4)M3a',
		'15.1(4)M4',
		'15.1(4)M5',
		'15.1(4)M6',
		'15.1(4)M7',
		'15.1(4)M8',
		'15.1(4)M9',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(1)GC',
		'15.2(1)GC1',
		'15.2(1)GC2',
		'15.2(1)SY',
		'15.2(1)SY0a',
		'15.2(1)SY1',
		'15.2(1)SY1a',
		'15.2(1)SY2',
		'15.2(1)SY3',
		'15.2(1)T',
		'15.2(1)T1',
		'15.2(1)T2',
		'15.2(1)T3',
		'15.2(1)T3a',
		'15.2(1)T4',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2)E4',
		'15.2(2)E5',
		'15.2(2)E5a',
		'15.2(2)EB',
		'15.2(2)EB1',
		'15.2(2)EB2',
		'15.2(2)GC',
		'15.2(2)SY',
		'15.2(2)SY1',
		'15.2(2)SY2',
		'15.2(2)T',
		'15.2(2)T1',
		'15.2(2)T2',
		'15.2(2)T3',
		'15.2(2)T4',
		'15.2(2a)E1',
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3)E2',
		'15.2(3)E3',
		'15.2(3)GC',
		'15.2(3)GC1',
		'15.2(3)T',
		'15.2(3)T1',
		'15.2(3)T2',
		'15.2(3)T3',
		'15.2(3)T4',
		'15.2(3a)E',
		'15.2(3m)E2',
		'15.2(4)E',
		'15.2(4)GC',
		'15.2(4)GC1',
		'15.2(4)GC2',
		'15.2(4)GC3',
		'15.2(4)M',
		'15.2(4)M1',
		'15.2(4)M10',
		'15.2(4)M11',
		'15.2(4)M2',
		'15.2(4)M3',
		'15.2(4)M4',
		'15.2(4)M5',
		'15.2(4)M6',
		'15.2(4)M6a',
		'15.2(4)M7',
		'15.2(4)M8',
		'15.2(4)M9',
		'15.3(1)SY',
		'15.3(1)SY2',
		'15.3(1)T',
		'15.3(1)T1',
		'15.3(1)T2',
		'15.3(1)T3',
		'15.3(1)T4',
		'15.3(2)T',
		'15.3(2)T1',
		'15.3(2)T2',
		'15.3(2)T3',
		'15.3(2)T4',
		'15.3(3)M',
		'15.3(3)M1',
		'15.3(3)M2',
		'15.3(3)M3',
		'15.3(3)M4',
		'15.3(3)M5',
		'15.3(3)M6',
		'15.3(3)M7',
		'15.3(3)M9',
		'15.4(1)CG',
		'15.4(1)CG1',
		'15.4(1)SY',
		'15.4(1)SY1',
		'15.4(1)T',
		'15.4(1)T1',
		'15.4(1)T2',
		'15.4(1)T3',
		'15.4(1)T4',
		'15.4(2)CG',
		'15.4(2)T',
		'15.4(2)T1',
		'15.4(2)T2',
		'15.4(2)T3',
		'15.4(2)T4',
		'15.4(3)M',
		'15.4(3)M1',
		'15.4(3)M2',
		'15.4(3)M3',
		'15.4(3)M4',
		'15.4(3)M5',
		'15.4(3)M6',
		'15.4(3)M6a',
		'15.4(3)M7',
		'15.5(1)T',
		'15.5(1)T1',
		'15.5(1)T2',
		'15.5(1)T3',
		'15.5(2)T',
		'15.5(2)T1',
		'15.5(2)T2',
		'15.5(2)T3',
		'15.5(2)T4',
		'15.5(3)M0a',
		'15.5(3)M1',
		'15.5(3)M2',
		'15.5(3)M4',
		'15.5(3)M4a',
		'15.5(3)M5',
		'15.5(3)S5',
		'15.6(1)T',
		'15.6(1)T0a',
		'15.6(1)T1',
		'15.6(1)T2',
		'15.6(2)T',
		'15.6(2)T1',
		'15.6(2)T2',
		'15.6(3)M',
		'15.6(3)M0a',
		'15.6(3)M1',
		'15.6(3)M1b',
		'15.6(3)M2' );

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

