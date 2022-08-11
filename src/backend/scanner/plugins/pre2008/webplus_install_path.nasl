###################################################################
# OpenVAS Vulnerability Test
# $Id: webplus_install_path.nasl 11998 2018-10-20 18:17:12Z cfischer $
#
# Talentsoft Web+ reveals install path
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12074");
  script_version("$Revision: 11998 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 20:17:12 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Talentsoft Web+ reveals install path");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Kyger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197");

  script_tag(name:"solution", value:"Apply the vendor-supplied patch.");

  script_tag(name:"summary", value:"The remote host appears to be running Web+ Application Server which
  is affected by an information disclosure flaw.");

  script_tag(name:"insight", value:"The version of Web+ installed on the remote host reveals the physical
  path of the application when it receives a script file error.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/webplus.exe?script=vt_test";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( "Web+ Error Message" >< res ) {
    path = strstr( res, " '" );
    path = ereg_replace( pattern:" and.*$", replace:"", string:path );
    report = path;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );