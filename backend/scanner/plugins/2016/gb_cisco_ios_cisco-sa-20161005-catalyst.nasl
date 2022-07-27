###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20161005-catalyst.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco IOS Software for Cisco Catalyst 6500 Series Switches and 7600 Series Routers ACL Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106330");
  script_cve_id("CVE-2016-6422");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12313 $");

  script_name("Cisco IOS Software for Cisco Catalyst 6500 Series Switches and 7600 Series Routers ACL Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-catalyst");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the ternary content addressable memory (TCAM) share
access control list (ACL) functionality of Cisco IOS Software running on Supervisor Engine 720 and Supervisor
Engine 32 Modules for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers could allow an
unauthenticated, remote attacker to bypass access control entries (ACEs) in a port access control list (PACL).");

  script_tag(name:"insight", value:"The vulnerability is due to the improper implementation of PACL logic for
ACEs that include a greater than operator, a less than operator, a tcp flag, the established keyword, or the
range keyword. An attacker could exploit this vulnerability by sending packets that meet one or more filter
criteria through an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass the filters defined
in the PACL for a targeted system.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 10:27:02 +0700 (Thu, 06 Oct 2016)");
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

if( version == '12.2(33)SXJ9' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

