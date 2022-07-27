###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-201600208-ucm.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco Unified Communications Manager Information Disclosure Vulnerability
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105542");
  script_cve_id("CVE-2016-1317");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 14181 $");

  script_name("Cisco Unified Communications Manager Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83103");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-201600208-ucm");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by browsing to a specific URL.
  An exploit could allow the attacker to view entity and table names.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient protection of database tables.");
  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"A vulnerability in the web framework of Cisco Unified Communications Manager could
  allow an authenticated, remote attacker to view sensitive data.");
  script_tag(name:"affected", value:"Cisco Unified Communications Manager Release 11.5(0.98000.480) is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-12 14:48:29 +0100 (Fri, 12 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

# example for detected version: 11.0.1.10000-10
vers = str_replace( string:vers, find:"-", replace:"." );

if( vers == '11.5.0.98000.480' )
{
  report = report_fixed_ver(  installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );