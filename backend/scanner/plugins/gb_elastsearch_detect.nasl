###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastsearch_detect.nasl 10400 2018-07-04 14:14:24Z cfischer $
#
# Elasticsearch and Logstash Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105031");
  script_version("2019-03-27T22:08:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-27 22:08:25 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2014-05-22 15:00:02 +0200 (Thu, 22 May 2014)");

  script_name("Elasticsearch and Logstash Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9200);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Check for the version of Elasticsearch.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply. Once a Elasticsearch service was detected
  it is assumed that Logstash is installed in the same version (ELK Stack).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:9200 );
if( ! buf = http_get_cache( item:"/", port:port ) ) exit( 0 );

if( "application/json" >< buf && ( "build_hash" >< buf || "build_timestamp" >< buf || "build_date" >< buf ) &&
    "lucene_version" >< buf && ( "elasticsearch" >< buf || "You Know, for Search" >< buf ) ) {

  version      = "unknown";
  elastic_cpe  = "cpe:/a:elasticsearch:elasticsearch";
  logstash_cpe = "cpe:/a:elasticsearch:logstash";
  install      = "/";

  vers = eregmatch( string:buf, pattern:'number" : "([0-9a-z.]+)",', icase:TRUE );
  if( ! isnull( vers[1] ) ) {
    version       = chomp( vers[1] );
    elastic_cpe  += ':' + version;
    logstash_cpe += ':' + version;
  }

  url = "/_cat/indices?v";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( "health" >< buf || "status" >< buf || "index" >< buf ) {
    extra  = "Collected information (truncated) from " + report_vuln_url( port:port, url:url, url_only:TRUE ) + ' :\n\n';
    extra += substr( buf, 0, 1000 );
    set_kb_item( name:"elasticsearch/noauth", value:TRUE );
    set_kb_item( name:"elasticsearch/" + port + "/noauth", value:TRUE );
  }

  # nb: Note that we're registering Logstash here as well until
  # we're finding a way to detect Logstash on port 5044/tcp
  set_kb_item( name:"www/" + port + "/elasticsearch", value:version );
  set_kb_item( name:"elasticsearch/installed", value:TRUE );
  set_kb_item( name:"www/" + port + "/logstash", value:version );
  set_kb_item( name:"logstash/installed", value:TRUE );

  register_product( cpe:elastic_cpe, location:install, port:port );
  register_product( cpe:logstash_cpe, location:install, port:0 );

  report  = build_detection_report( app:"Elasticsearch",
                                    version:version,
                                    install:install,
                                    cpe:elastic_cpe,
                                    extra:extra,
                                    concluded:vers[0] );
  report += '\n\n';
  report += build_detection_report( app:"Logstash",
                                    version:version,
                                    install:install,
                                    cpe:logstash_cpe,
                                    concluded:"Existence of Elasticsearch service, the actual version of the Logstash service might differ." );

  log_message( port:port, data:report );
}

exit( 0 );
