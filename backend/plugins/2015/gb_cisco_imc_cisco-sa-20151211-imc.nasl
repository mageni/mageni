###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_imc_cisco-sa-20151211-imc.nasl 14184 2019-03-14 13:29:04Z cfischer $
#
# Cisco Integrated Management Controller Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:integrated_management_controller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105485");
  script_cve_id("CVE-2015-6399");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_version("$Revision: 14184 $");

  script_name("Cisco Integrated Management Controller Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151211-imc");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending a crafted HTTP request to the IMC.
  A successful exploit could allow the attacker to cause the IMC to become inaccessible via the IP interface, resulting in a
  denial of service (DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete sanitization of input for certain parameters.");

  script_tag(name:"solution", value:"See vendor advisory");
  script_tag(name:"summary", value:"A vulnerability in Cisco Integrated Management Controller (IMC) could allow an authenticated,
  remote attacker to make the IMC IP interface inaccessible.");
  script_tag(name:"affected", value:"Cisco IMC releases prior to 2.0(9) are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-15 11:41:43 +0100 (Tue, 15 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_imc_detect.nasl");
  script_mandatory_keys("cisco_imc/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:version, find:")", replace:'' );
version = str_replace( string:version, find:"(", replace:'.' );

if( version_is_less( version:version, test_version:"2.0.9") )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     2.0(9)';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );