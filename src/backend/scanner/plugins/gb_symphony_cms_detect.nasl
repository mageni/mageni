###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Symphony CMS Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801219");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_name("Symphony CMS Version Detection");

  script_tag(name:"summary", value:"This script finds the running Symphony CMS
  version and saves the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

cmsPort = get_http_port(default:80);
if(!can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir(make_list_unique("/", "/cms", "/symphony", cgi_dirs( port:cmsPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item: dir + "/symphony/", port:cmsPort);
  rcvRes = http_keepalive_send_recv( port:cmsPort, data:sndReq );
  sndReq2 = http_get( item: dir + "/index.php?mode=administration", port:cmsPort);
  rcvRes2 = http_keepalive_send_recv( port:cmsPort, data:sndReq2);

  if( ( rcvRes =~ "HTTP/1.. 200" && ( "<title>Login &ndash; Symphony</title>" >< rcvRes || "<title>Login &ndash; Symphony CMS</title>" >< rcvRes || "<h1>Symphony</h1>" >< rcvRes || "<legend>Login</legend>" >< rcvRes ) ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && ( "<title>Login &ndash; Symphony</title>" >< rcvRes2 || "<title>Login &ndash; Symphony CMS</title>" >< rcvRes2 || "<h1>Symphony</h1>" >< rcvRes2 || "<legend>Login</legend>" >< rcvRes2 ) ) ) {

    req = http_get( item: dir + "/manifest/logs/main", port:cmsPort);
    res = http_keepalive_send_recv(port:cmsPort, data:req);

    version = "unknown";

    ver = eregmatch( pattern:"[v|V]ersion: ([0-9.]+)", string:res);
    if(!isnull(ver[1])){
      version = ver[1];
    } else
    {
      # nb: for Symphony 1.7.x
      req = http_get( item: dir + "/README", port:cmsPort);
      res = http_keepalive_send_recv( port:cmsPort, data:req );
      ver = eregmatch( pattern:"Symphony ([0-9.]+)", string:res);
      if(!isnull(ver[1])){
        version = ver[1];
      } else
      {
        # nb: for Symphony 2.x
        req = http_get( item: dir + "/README.markdown", port:cmsPort);
        res = http_keepalive_send_recv( port:cmsPort, data:req);
        ver = eregmatch(pattern:"[v|V]ersion: ([0-9.]+)", string:res);
        if(!isnull(ver[1]))version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + cmsPort + "/symphony", value:tmp_version );
    set_kb_item( name:"symphony/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:symphony-cms:symphony_cms:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:symphony-cms:symphony_cms';

    register_product( cpe:cpe, location:install, port:cmsPort);
    log_message( data:build_detection_report( app:"Symphony CMS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded: ver[0] ),
                                              port:cmsPort);
  }
}

exit( 0 );
