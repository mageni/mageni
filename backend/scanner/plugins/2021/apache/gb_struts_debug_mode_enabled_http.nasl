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
  script_oid("1.3.6.1.4.1.25623.1.0.117689");
  script_version("2021-09-22T11:50:44+0000");
  script_tag(name:"last_modification", value:"2021-09-23 11:24:26 +0000 (Thu, 23 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-21 13:11:29 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Apache Struts Debug Mode Enabled - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "gb_vmware_vcenter_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("www/action_jsp_do");

  script_tag(name:"summary", value:"The remote host is running an Apache Struts application with
  enabled debug mode.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Usage of debug mode in a production environment can lead to
  exposing vulnerable information of the application.");

  script_tag(name:"affected", value:"Any Apache Struts 2 application exposing the debug mode output
  to the public / using it in a production environment.");

  script_tag(name:"solution", value:"Disable the debug mode in a production environment.");

  script_xref(name:"URL", value:"https://struts.apache.org/core-developers/debugging.html");
  script_xref(name:"URL", value:"https://struts.apache.org/core-developers/debugging-interceptor.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

urls = make_list();

foreach ext( make_list( "action", "do", "jsp" ) ) {
  exts = http_get_kb_file_extensions( port:port, host:host, ext:ext );
  if( exts && is_array( exts ) ) {
    urls = make_list( urls, exts );
  }
}

if( get_kb_item( "vmware/vcenter/http/detected" ) )
  urls = make_list_unique( "/statsreport/", urls );

x = 0;
vuln = FALSE;
max_items = 10;
cur_items = 0;
report = "The remote host has the debug mode enabled for the following URL(s): (output limited to " + max_items + ' entries)\n';

foreach url( urls ) {

  x++;
  url += "?debug=xml";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( egrep( pattern:"^\s*<debug>", string:res, icase:FALSE ) &&
      egrep( pattern:"^\s*<struts\.actionMapping>", string:res, icase:FALSE ) ) {
    vuln = TRUE;
    cur_items++;
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    if( cur_items >= max_items )
      break;
  }

  if( x > 25 ) # nb: No need to continue, the system is very unlikely affected...
    break;
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );