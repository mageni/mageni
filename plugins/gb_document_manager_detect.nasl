###############################################################################
# OpenVAS Vulnerability Test
#
# Document Manager Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800477");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Document Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Document Manager version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

dmPort = get_http_port(default:80);

if( !can_host_php( port:dmPort ) ) exit( 0 );

foreach path (make_list_unique("/", "/dmanager", cgi_dirs(port:dmPort)))
{

  install = path;
  if(path == "/") path = "";

  sndReq = http_get(item: path + "/php/login.php", port:dmPort);
  rcvRes = http_keepalive_send_recv(port:dmPort, data:sndReq);

  if("Document Manager" >< rcvRes || "Porte Documents" >< rcvRes)
  {
    version = "unknown";

    dmVer = eregmatch(pattern:"version ([0-9.]+)", string:rcvRes);
    if(dmVer[1] != NULL){
      version = dmVer[1];
    }
    else
    {
      sndReq = http_get(item: path + "/php/version", port:dmPort);
      rcvRes = http_keepalive_send_recv(port:dmPort, data:sndReq, bodyonly:1);
      if(!isnull(rcvRes))
      {
        dmVer = eregmatch(pattern:"([0-9.]+)", string:rcvRes);
        if(dmVer[1] != NULL){
          version = dmVer[1];
        }
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + dmPort + "/DocManager", value:tmp_version);
    set_kb_item(name:"docmanager/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:dmanager:documentmanager:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:dmanager:documentmanager';

    register_product( cpe:cpe, location:install, port:dmPort );

    log_message( data: build_detection_report( app:"Document Manager",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: dmVer[0]),
                                               port:dmPort);

  }
}
