###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_manager_cisco-sa-20160914-ucs.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Unified Computing System Command Line Interface Privilege Escalation Vulnerability
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
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:cisco:unified_computing_system_software';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106254");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-16 12:38:55 +0700 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-6402");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Computing System Command Line Interface Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_mandatory_keys("cisco_ucs_manager/installed");

  script_tag(name:"summary", value:"A vulnerability in the command-line interface (CLI) of the Cisco Unified
Computing System (UCS) Manager and UCS 6200 Series Fabric Interconnects could allow an authenticated, local
attacker to access the underlying operating system with the privileges of the root user.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of user-supplied
input at the CLI.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by bypassing policy
restrictions and executing commands on the underlying operating system. The user needs to log in to the device
with valid user credentials to exploit this vulnerability.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-ucs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'2.2(1b)',
		'2.2(1c)',
		'2.2(1d)',
 		'2.2(1e)',
		'2.2(1f)',
		'2.2(1g)',
		'2.2(1h)',
		'2.2(2c)',
		'2.2(2c)A',
		'2.2(2d)',
		'2.2(2e)',
		'2.2(3a)',
		'2.2(3b)',
		'2.2(3c)',
		'2.2(3d)',
		'2.2(3e)',
		'2.2(3f)',
		'2.2(3g)',
		'2.2(4b)',
		'2.2(4c)',
		'2.2(5a)',
		'2.2(5b)A',
		'3.0(1c)',
		'3.0(1d)',
		'3.0(1e)',
		'3.0(2c)',
		'3.0(2d)' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit(0);
