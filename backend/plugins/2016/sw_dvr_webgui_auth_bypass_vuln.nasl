###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dvr_webgui_auth_bypass_vuln.nasl 12465 2018-11-21 13:24:34Z cfischer $
#
# Multiple DVR Devices Authentication Bypass And Remote Code Execution Vulnerabilities
#
# Authors:
# Christian Fischer <cfischer@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111088");
  script_version("$Revision: 12465 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 14:24:34 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-22 08:00:0 +0100 (Mon, 22 Feb 2016)");
  script_name("Multiple DVR Devices Authentication Bypass And Remote Code Execution Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.pentestpartners.com/blog/pwning-cctv-cameras/");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"summary", value:"This host is running a Digital Video Recorder (DVR)
  device and is prone to authentication bypass and remote code execution vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET method
  and check whether it is able to access admin panel of the device or execute remote commands.");

  script_tag(name:"insight", value:"The flaw is due to the device:

  - accepting access to the files /view2.html or /main.html if the two cookies 'dvr_usr'
  and 'dvr_pwd' have any value and the cookie 'dvr_camcnt' a value of 2, 4, 8 or 24.

  - providing an unauthenticated access to a web shell");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to:

  - gain access to the administration interface of the device and manipulate the device's settings

  - execute remote commands on the base system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
buf = http_get_cache( item:"/", port:port );

if( "erver: JAWS/1.0" >< banner || '<span lxc_lang="index_Remember_me">Remember me</span></p>' >< buf || "Network video client</span>" >< buf ) {

  url = '/shell?id';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( "uid=0(root) gid=0(root)" >< buf ) {
    report += "Remote code execution, " + report_vuln_url( port:port, url:url ) + '\n';
    vuln = 1;
  }

  foreach file ( make_list( "/view2.html", "/main.html" ) ) {

    req = http_get( item:file, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( '<span lxc_lang="view_Channel">Channel</span>' >< buf || '<a id="connectAll" lxc_lang="view_Connect_all">' >< buf ) {
      report += "Authentication bypass, " + report_vuln_url( port:port, url:file ) + '\n';
      vuln = 1;
    }
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
