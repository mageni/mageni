# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117679");
  script_version("2021-09-17T07:29:47+0000");
  script_tag(name:"last_modification", value:"2021-09-17 10:28:54 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-16 10:49:32 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Apache Struts Config Browser Plugin Exposed (S2-043) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is exposing the Apache Struts Config Browser
  Plugin via HTTP.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Usage of the Config Browser Plugin in a production environment
  can lead to exposing vulnerable information of the application.");

  script_tag(name:"affected", value:"Any Apache Struts 2 version exposing the Config Browser Plugin
  to the public / using it in a production environment.");

  script_tag(name:"solution", value:"Please read the linked Security guideline and restrict access
  to the Config Browser Plugin or do not use in a production environment.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-043");
  script_xref(name:"Advisory-ID", value:"S2-043");
  script_xref(name:"URL", value:"http://struts.apache.org/security/#restrict-access-to-the-config-browser-plugin");
  script_xref(name:"URL", value:"https://struts.apache.org/plugins/config-browser/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

VULN = FALSE;
report = 'The Apache Struts Config Browser Plugin was found to be enabled / exposed on the following URL(s):\n';

foreach dir( make_list_unique( "/", "/struts", "/struts2-showcase", "/struts2-blank", "/struts2-basic",
                               "/struts2-mailreader", "/struts2-portlet", "/struts2-rest-showcase",
                               "/struts-cookbook", "/struts-examples", "/starter", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  # nb: From the plugins page:
  # In most cases (if you are using the default ActionMapper), the URL is something like
  # http://localhost:8080/starter/config-browser/index.action or
  # http://localhost:8080/starter/config-browser/index
  foreach url( make_list( dir + "/config-browser/index.action",
                          dir + "/config-browser/index" ) ) {

    res = http_get_cache( item:url, port:port );
    if( ! res || res !~ "HTTP/1\.[01] 200" )
      continue;

    # See e.g.:
    # https://github.com/apache/struts/blob/ce335f19c48754b76d87cc2553be37f555e024ba/plugins/config-browser/src/main/resources/config-browser/page-header.ftl#L33-L35
    if( "Struts Configuration Browser > " >< res ) {
      VULN = TRUE;
      report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break; # nb: No need to test e.g. index if index.action worked
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );