###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20160928-smi.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco IOS XE Software Smart Install Memory Leak Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106315");
  script_cve_id("CVE-2016-6385");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco IOS XE Software Smart Install Memory Leak Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-smi");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The Smart Install client feature in Cisco IOS XE Software contains a
vulnerability that could allow an unauthenticated, remote attacker to cause a memory leak and eventual denial
of service (DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect handling of image list parameters.
An attacker could exploit this vulnerability by sending crafted Smart Install packets to TCP port 4786.");

  script_tag(name:"impact", value:"A successful exploit could cause the device to leak memory and eventually
reload, resulting in a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 15:47:20 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'3.2.0JA',
		'3.8.0E',
		'3.8.1E',
		'3.8.2E',
		'3.2.0SE',
		'3.2.1SE',
		'3.2.2SE',
		'3.2.3SE',
		'3.3.0SE',
		'3.3.1SE',
		'3.3.2SE',
		'3.3.3SE',
		'3.3.4SE',
		'3.3.5SE',
		'3.3.0XO',
		'3.3.1XO',
		'3.3.2XO',
		'3.5.0E',
		'3.5.1E',
		'3.5.2E',
		'3.5.3E',
		'3.6.4E',
		'3.6.0E',
		'3.6.1E',
		'3.6.2aE',
		'3.6.2E',
		'3.6.3E',
		'3.7.3E',
		'3.7.5E',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E' );

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

