###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20160928-ipdr.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco IOS Software IP Detail Record Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106309");
  script_cve_id("CVE-2016-6379");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco IOS Software IP Detail Record Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ipdr");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the IP Detail Record (IPDR) code of Cisco IOS Software
could allow an unauthenticated, remote attacker to cause an affected system to reload.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of IPDR packets. An
attacker could exploit this vulnerability by sending crafted IPDR packets to an affected system.");

  script_tag(name:"impact", value:"A successful exploit could cause the device to reload, resulting in a
denial of service (DoS) condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 15:18:08 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'12.2(33)CX',
		'12.2(33)CY',
		'12.2(33)CY1',
		'12.2(33)SCH',
		'12.2(33)SCH0a',
		'12.2(33)SCH1',
		'12.2(33)SCH2',
		'12.2(33)SCH2a',
		'12.2(33)SCH3',
		'12.2(33)SCH4',
		'12.2(33)SCH5',
		'12.2(33)SCH6',
		'12.2(33)SCI',
		'12.2(33)SCI1',
		'12.2(33)SCI1a',
		'12.2(33)SCI3' );

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

