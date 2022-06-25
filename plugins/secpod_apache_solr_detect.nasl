###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_solr_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Apache Solr Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Updated by: kashinath T <tkashinath@sepcod.com>
# Updated to support detection of newer versions.
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.903506");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-01-29 13:13:35 +0530 (Wed, 29 Jan 2014)");
  script_name("Apache Solr Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8983);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Apache Solr.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

solrPort = get_http_port( default:8983 );

foreach dir( make_list_unique( "/", "/solr", "/apachesolr", cgi_dirs( port:solrPort ) ) )
{
  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/" , port:solrPort );

  if( rcvRes =~ "HTTP/1.. 200" && (">Solr Admin<" >< rcvRes || "Solr admin page" >< rcvRes )) {
    version = "unknown";

    req = http_get(item: dir + "/admin/info/system", port: solrPort);
    rcvRes = http_keepalive_send_recv( port:solrPort, data:req, bodyonly:TRUE );

    vers = eregmatch(pattern: 'solr-spec-version">([0-9.]+)', string: rcvRes);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "Apache/Solr/Version", value: version);
      concurl = dir + "/admin/info/system";
    }
    else {
      req = http_get( item: dir + "/admin/registry.jsp", port:solrPort );
      rcvRes = http_keepalive_send_recv( port:solrPort, data:req, bodyonly:TRUE );

      vers = eregmatch( string:rcvRes, pattern:"lucene-spec-version>([0-9.]+)", icase:TRUE );
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "Apache/Solr/Version", value: version);
        concurl = dir + "/admin/registry.jsp";
      }
      else {
        req = http_get( item: dir + "/#/", port:solrPort );
        rcvRes = http_keepalive_send_recv( port:solrPort, data:req, bodyonly:TRUE );

        vers = eregmatch( string:rcvRes, pattern:'js/require.js?_=([0-9.]+)', icase:TRUE );
        if (!isnull(vers[1])) {
          version = vers[1];
          set_kb_item(name: "Apache/Solr/Version", value: version);
          concurl = dir + "/#/";
        }
      }
    }

    set_kb_item(name:"Apache/Solr/Installed", value:TRUE);

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:solr:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:solr";

    register_product( cpe:cpe, location:install, port:solrPort );

    log_message( data: build_detection_report( app:"Apache Solr",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:vers[0], concludedUrl: concurl ),
                 port:solrPort );
    exit(0);
  }
}

exit(0);
