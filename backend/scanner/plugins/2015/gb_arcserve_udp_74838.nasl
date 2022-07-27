###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcserve_udp_74838.nasl 12398 2018-11-19 07:18:06Z ckuersteiner $
#
# Arcserve Unified Data Protection Multiple Vulnerabilities
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

CPE = "cpe:/a:arcserve:arcserve_unified_data_protection";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105295");
  script_bugtraq_id(74838);
  script_cve_id("CVE-2015-4069", "CVE-2015-4068");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_version("$Revision: 12398 $");

  script_name("Arcserve Unified Data Protection Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74845");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain sensitive information
that may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"Arcserve Unified Data Protection is prone to multiple information-
disclosure vulnerabilities and multiple directory traversal vulnerabilities.");
  script_tag(name:"affected", value:"Arcserve UDP before 5.0 Update 4");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-19 08:18:06 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-06-11 17:46:01 +0200 (Thu, 11 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_arcserve_udp_detect.nasl");
  script_require_ports("Services/www", 8014);
  script_mandatory_keys("arcserve_udp/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_greater( version:vers, test_version:"5.0" ) ) exit( 99 );
if( version_is_less( version:vers, test_version:"5.0" ) ) VULN = TRUE;

if( ! VULN )
{
  build = get_kb_item("arcserve_udp/build");
  typ = get_kb_item("arcserve_udp/soap_typ");
  if( typ == 'linux' )
  {
    if( build )
    {
      if( version_is_less( version:build, test_version:"3230.1" ) ) VULN = TRUE;
    }
  }
  else if( typ == "windows" )
  {
    update = get_kb_item("arcserve_udp/update");
    if( int( update ) < 4 ) VULN = TRUE;
  }
}

if( VULN )
{
  report = 'Installed version: ' + vers + '\n';

  if( build && ! update )
    report += 'Build:             ' + build + '\n' + 'Fixed build:       3230.1 (Update 4)\n';
  else if( update )
    report += 'Build:             ' + build + '\n' + 'Installed update:  ' + update + '\n' + 'Fixed update:      4\n';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
