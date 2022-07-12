###############################################################################
# OpenVAS Vulnerability Test
# $Id: cubecart_37065.nasl 12151 2018-10-29 13:19:19Z cfischer $
#
# CubeCart 'productId' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100360");
  script_version("$Revision: 12151 $");
  script_cve_id("CVE-2009-4060");
  script_bugtraq_id(37065);
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 14:19:19 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-11-24 12:49:20 +0100 (Tue, 24 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CubeCart 'productId' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37065");
  script_xref(name:"URL", value:"http://forums.cubecart.com/index.php?showtopic=39900");

  script_tag(name:"summary", value:"CubeCart is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"The issue affects CubeCart 4.3.6. Prior versions may also be affected.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"4.3.0", test_version2:"4.3.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.7" );
  security_message( port:port, data:report );
}

exit( 0 );