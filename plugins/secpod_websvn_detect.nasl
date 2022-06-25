###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_websvn_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# WebSVN script version detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900440");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WebSVN version detection");

  script_tag(name:"summary", value:"The script detects the version of WebSVN
  and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

websvnPort = get_http_port( default:80 );
if(!can_host_php(port:websvnPort)) exit(0);

foreach dir (make_list_unique("/", "/websvn", "/svn", cgi_dirs(port:websvnPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:websvnPort);

  if("WebSVN" >!< rcvRes) {
    rcvRes = http_get_cache(item:string(dir, "/listing.php"), port:websvnPort);
  }

  if("WebSVN" >< rcvRes && "Subversion" >< rcvRes)
  {
    svnVer = eregmatch(pattern:"WebSVN ([0-9.]+)", string:rcvRes);
    if(svnVer[1] == NULL){
       svnVer = "Unknown";
    } else{
      svnVer = svnVer[1];
    }

    set_kb_item(name:"WebSVN/Installed", value:TRUE);
    if( svnVer != "Unknown" ){
      set_kb_item(name:"www/" + websvnPort + "/WebSVN", value:svnVer);
    }
    register_and_report_cpe( app:"WebSVN", ver:svnVer, concluded:svnVer, base:"cpe:/a:tigris:websvn:", expr:"^([0-9.]+)", insloc:install, regPort:websvnPort );
    exit(0);
  }
}
