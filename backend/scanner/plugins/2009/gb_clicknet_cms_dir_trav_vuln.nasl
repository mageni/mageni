###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clicknet_cms_dir_trav_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Clicknet CMS 'index.php' Directory Traversal Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:clicknet:clicknet_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800903");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2325");
  script_name("Clicknet CMS 'index.php' Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clicknet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("clicknetcms/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35607");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9037");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1736");

  script_tag(name:"affected", value:"Clicknet CMS version 2.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in 'side' parameter in index.php which
  is not adequately sanitised that may lead to directory traversal attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has Clicknet CMS installed and is prone to Directory
  Traversal vulnerability.");

  script_tag(name:"impact", value:"Successful attacks will allow attackers to read arbitrary files
  via a '..' (dot dot) sequences.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos['version'];
dir = infos['location'];
if( dir == "/" ) dir = "";

url = dir + "/index.php?side=../index";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "DOCUMENT_ROOT" >< rcvRes && "explode" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_less_equal( version:vers, test_version:"2.1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"None available" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );