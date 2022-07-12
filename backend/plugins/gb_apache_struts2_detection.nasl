###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_detection.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Apache Struts2 Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107006");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-01 06:40:16 +0200 (Wed, 01 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Default Apache Struts2 Web Applications Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "apache_server_info.nasl", "gb_apache_struts_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Apache Struts2

  The script detects the version of Apache Struts2 on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:7080 );
banner = get_http_banner( port:port );

sndReq = http_get( item: "/manager/html", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

# TODO: Recheck, there could be also a reverse proxy running
if( "Coyote" >!< banner && "tomcat" >!< banner ) {
  exit( 0 );
}

# TBD: What's the purpose of this? See also set_kb_item for apacheVer below
tmpVer = eregmatch( pattern:"Server: Apache-Coyote/([0-9]+\.[0-9]+?)", string:banner );
if( tmpVer[0] ) apacheVer = tmpVer[0];

app_report = ""; # nb: To make openvas-nasl-lint happy...
version = "unknown";

#finding web apps
foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach url( make_list( dir, dir + "/struts2-blank", dir + "/struts2-basic",
                          dir + "/struts2-mailreader", dir + "/struts2-portlet",
                          dir + "/struts2-rest-showcase", dir + "/struts2-showcase",
                          dir + "/docs" ) ) {

    found_page = "/index.action";
    if( url == dir + "/struts2-blank" ) found_page = "/example/HelloWorld.action";
    if( url == dir + "/struts2-mailreader" ) found_page = "/Welcome.do";

    sndReq = http_get( item:dir + url + found_page, port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    # TODO: That could match on too many servers
    if( rcvRes =~ "HTTP/1\.[0-9]+ 200" ) {

      if( "Struts2" >< rcvRes || "Apache Struts" >< rcvRes ) {
        # TODO: Recheck on build_detect_report below (This would set a version like "Struts 2 1.0.0")
        strutsVer = eregmatch (pattern:" Struts2 ([0-9]+).([0-9]+).([0-9]+).([0-9]+)" , string:rcvRes );
        foundapp = dir + url + found_page;
        app_report += '\n' + report_vuln_url( url:foundapp, port:port, url_only:TRUE );
      }
    }
  }
}

if( foundapp ) {
  set_kb_item( name:'ApacheStruts/FoundApp', value:foundapp );
}
else
 exit( 0 );

if( app_report ) {
  report = 'The following default Apache Struts2 Web Applications have been discovered :\n' + app_report;
  log_message( port:port, data:report ); #TODO: Move to extra check in build_detection_report
}

if( get_kb_item( "ApacheStruts/installed" ) ) {
  exit( 0 );
}

# TBD: Why apacheVer and not strutsVer?
set_kb_item( name:"www/" + port + "/Struts", value:apacheVer );
set_kb_item( name:'ApacheStruts/installed', value:TRUE );

cpe = 'cpe:/a:apache:struts';
register_product( cpe:cpe, location:install, port:port );
log_message( data:build_detection_report( app:"Apache Struts",
                                          version:strutsVer,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version ),
                                          port:port );

exit( 0 );
