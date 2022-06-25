###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_cisco-sa-20160817-asa-cli.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Adaptive Security Appliance CLI Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106184");
  script_cve_id("CVE-2016-6367");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12096 $");

  script_name("Cisco Adaptive Security Appliance CLI Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-cli");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-56516");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the command-line interface (CLI) parser of Cisco
  Adaptive Security Appliance (ASA) Software could allow an authenticated, local attacker to create a denial
  of service (DoS) condition or potentially execute arbitrary code. An attacker could exploit this vulnerability
  by invoking certain invalid commands in an affected device.

  Cisco has released software updates that address this vulnerability. There are no workarounds that address
  this vulnerability. This advisory is available at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-18 12:25:55 +0700 (Thu, 18 Aug 2016)");
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
		'7.0.1.4',
		'7.0.1',
		'7.0.2',
		'7.0.3',
		'7.0.4',
		'7.0.4.2',
		'7.0.5',
		'7.0.5.12',
		'7.0.6',
		'7.0.6.4',
		'7.0.6.8',
		'7.0.6.18',
		'7.0.6.22',
		'7.0.6.26',
		'7.0.6.29',
		'7.0.6.32',
		'7.0.7',
		'7.0.7.1',
		'7.0.7.4',
		'7.0.7.9',
		'7.0.7.12',
		'7.0.8',
		'7.0.8.2',
		'7.0.8.8',
		'7.0.8.12',
		'7.0.8.13',
		'7.1.2',
		'7.1.2.16',
		'7.1.2.20',
		'7.1.2.24',
		'7.1.2.28',
		'7.1.2.38',
		'7.1.2.42',
		'7.1.2.46',
		'7.1.2.49',
		'7.1.2.53',
		'7.1.2.61',
		'7.1.2.64',
		'7.1.2.72',
		'7.1.2.81',
		'7.2.1',
		'7.2.1.9',
		'7.2.1.13',
		'7.2.1.19',
		'7.2.1.24',
		'7.2.2',
		'7.2.2.6',
		'7.2.2.10',
		'7.2.2.14',
		'7.2.2.18',
		'7.2.2.19',
		'7.2.2.22',
		'7.2.2.34',
		'7.2.3',
		'7.2.3.1',
		'7.2.3.12',
		'7.2.3.16',
		'7.2.4',
		'7.2.4.6',
		'7.2.4.9',
		'7.2.4.18',
		'7.2.4.25',
		'7.2.4.27',
		'7.2.4.30',
		'7.2.4.33',
		'7.2.5',
		'7.2.5.2',
		'7.2.5.4',
		'7.2.5.7',
		'7.2.5.8',
		'7.2.5.10',
		'7.2.5.12',
		'7.2.5.16',
		'8.0.1.2',
		'8.0.2',
		'8.0.2.11',
		'8.0.2.15',
		'8.0.3',
		'8.0.3.6',
		'8.0.3.12',
		'8.0.3.19',
		'8.0.4',
		'8.0.4.3',
		'8.0.4.9',
		'8.0.4.16',
		'8.0.4.23',
		'8.0.4.25',
		'8.0.4.28',
		'8.0.4.31',
		'8.0.4.32',
		'8.0.4.33',
		'8.0.5',
		'8.0.5.20',
		'8.0.5.23',
		'8.0.5.25',
		'8.0.5.27',
		'8.0.5.28',
		'8.0.5.31',
		'8.1.1',
		'8.1.1.6',
		'8.1.2',
		'8.1.2.13',
		'8.1.2.15',
		'8.1.2.16',
		'8.1.2.19',
		'8.1.2.23',
		'8.1.2.24',
		'8.1.2.49',
		'8.1.2.50',
		'8.1.2.55',
		'8.1.0.104',
		'8.1.2.56',
		'8.2.0.45',
		'8.2.1',
		'8.2.1.11',
		'8.2.2',
		'8.2.2.9',
		'8.2.2.10',
		'8.2.2.12',
		'8.2.2.16',
		'8.2.2.17',
		'8.2.3',
		'8.2.4',
		'8.2.4.1',
		'8.2.4.4',
		'8.2.5',
		'8.2.5.13',
		'8.2.5.22',
		'8.2.5.26',
		'8.2.5.33',
		'8.2.5.40',
		'8.2.5.41',
		'8.2.5.46',
		'8.2.5.48',
		'8.2.5.50',
		'8.2.5.52',
		'8.2.5.55',
		'8.2.5.57',
		'8.3.1',
		'8.3.1.1',
		'8.3.1.4',
		'8.3.1.6',
		'8.3.2',
		'8.3.2.4',
		'8.3.2.13',
		'8.3.2.23',
		'8.3.2.25',
		'8.3.2.31',
		'8.3.2.33',
		'8.3.2.34',
		'8.3.2.37',
		'8.3.2.39',
		'8.3.2.40',
		'8.3.2.41',
		'8.3.2.44' );

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

