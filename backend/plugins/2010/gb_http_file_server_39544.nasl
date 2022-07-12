###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_39544.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# HTTP File Server Security Bypass and Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100585");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_bugtraq_id(39544);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("HTTP File Server Security Bypass and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39544");
  script_xref(name:"URL", value:"http://www.rejetto.com/hfs/?f=intro");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/hfsref-adv.txt");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"affected", value:"HttpFileServer version 2.2e and prior.");

  script_tag(name:"solution", value:"Update to version 2.2f or later.");

  script_tag(name:"summary", value:"HTTP File Server is prone to multiple vulnerabilities including a security-
  bypass issue and a denial-of-service issue.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to download files from
  restricted directories within the context of the application or cause denial-of-service conditions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! hfsPort = get_app_port( cpe:CPE ) ) exit(0);
if( ! hfsVer = get_app_version( cpe:CPE, port:hfsPort ) ) exit(0);

if( version_is_less( version:hfsVer, test_version:"2.2f" ) ) {
  report = report_fixed_ver( installed_version: hfsVer, fixed_version: "2.2f" );
  security_message( port:hfsPort, data:report );
  exit( 0 );
}

exit( 99 );