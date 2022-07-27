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
  script_oid("1.3.6.1.4.1.25623.1.0.117195");
  script_version("2021-02-02T07:08:49+0000");
  script_cve_id("CVE-2000-1050", "CVE-2007-6672");
  script_tag(name:"last_modification", value:"2021-02-02 11:22:57 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-01 14:53:40 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Various Application Server '//WEB-INF' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/553235");
  script_xref(name:"URL", value:"https://svn.apache.org/repos/asf/tomcat/archive/tc3.2.x/tags/tc3.2.2.b3/container/RELEASE-NOTES");
  script_xref(name:"URL", value:"https://web.archive.org/web/20081015230304/http://www.igniterealtime.org/community/message/163752");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=97236316510117&w=2");

  script_tag(name:"summary", value:"Various application servers are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Mortbay Jetty version 6.1.5 and 6.1.6 (other older versions might be affected as well).

  - Apache Tomcat before version 3.2.1.

  - Ignite Realtime Openfire before version 3.4.4 (using an affected Jetty version).

  - Allaire JRUN 3.0

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from serving resources
  in the '/WEB-INF' and '/META-INF' directories of a web application archive directly to clients.

  In Tomcat for example, this means that URLs like:

  http://example.com:8080/examples/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application servers are prone to a vulnerability that exposes this information if the client requests
  a URL like this instead:

  http://example.com:8080/examples//WEB-INF/web.xml

  (note the double slash before 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might
  be able to gather additional info and/or sensitive data about the application / the application server.");

  script_tag(name:"solution", value:"The following vendor fixes are known:

  - Update Mortbay Jetty to version 6.1.7 or later.

  - Update Apache Tomcat to version 3.2.1 or later.

  - Update Ignite Realtime Openfire to version 3.4.4 or later.

  For other products please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet>$)";
extra_pattern = "^\s*</(web-app|servlet)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF/web.xml";
  res = http_get_cache( item:url, port:port );
  if( ! res )
    continue;

  # nb: Avoid false positives if the file is directly accessible (already checked by 2018/gb_sensitive_file_disclosures_http.nasl).
  if( egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) )
    continue;

  url = str_replace( string:url, find:"/WEB-INF/web.xml", replace:"//WEB-INF/web.xml" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
