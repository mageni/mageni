###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_pis_cisco-sa-20160406-remcode.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco Prime Infrastructure Remote Code Execution Vulnerability
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

CPE = "cpe:/a:cisco:prime_infrastructure";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105615");
  script_cve_id("CVE-2016-1291");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14181 $");

  script_name("Cisco Prime Infrastructure Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-remcode");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending an HTTP POST with crafted deserialized
  user data. An exploit could allow the attacker to execute arbitrary code with root-level privileges on the affected system, which
  could be used to conduct further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of HTTP user-supplied input.");
  script_tag(name:"solution", value:"Update to Cisco Prime Infrastructure 3.0.2 or newer");
  script_tag(name:"summary", value:"A vulnerability in the web interface of Cisco Prime Infrastructure could allow an unauthenticated,
  remote attacker to execute arbitrary code on a targeted system.");
  script_tag(name:"affected", value:"Cisco Prime Infrastructure prior to 3.0.2");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-21 11:49:04 +0200 (Thu, 21 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_pis_version.nasl");
  script_mandatory_keys("cisco_pis/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^3\." )
  if( version_is_less( version:version, test_version:'3.0.2' ) ) fix = '3.0.2';

if( version =~ "^2\." )
{
  if( version_is_less( version:version, test_version:'2.2.3' ) ) fix = '2.2.3 Update 4';
  if( version =~ "^2\.2\.3" )
  {
     if( installed_patches = get_kb_item( "cisco_pis/installed_patches" ) )
        if( "Update 4" >!< installed_patches ) fix = '2.2.3 Update 4';
  }
}

if( fix )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );