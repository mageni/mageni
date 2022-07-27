###############################################################################
# OpenVAS Vulnerability Test
#
# F-Secure Internet Gatekeeper Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103081");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("F-Secure Internet Gatekeeper Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9012);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running the F-Secure Internet Gatekeeper.");

  script_xref(name:"URL", value:"http://www.f-secure.com/en/web/business_global/products/email-web-filtering/internet-gatekeeper-for-linux");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("host_details.inc");

SCRIPT_DESC = "F-Secure Internet Gatekeeper Detection";

port = get_http_port(default:9012);

host = http_host_name(port:port);

url = string("/login.jsf");
buf = http_get_cache(item:url, port:port);
if(!buf)
  exit(0);

if("<title>F-Secure Anti-Virus Gateway for Linux</title>" >< buf)
{
  vers = string("unknown");
  install = "/";

  state = eregmatch(pattern:'id="javax.faces.ViewState" value="([^"]+)"', string:buf);

  if(!isnull(state[1])) {

    st = urlencode(str:state[1]);
    j_id_jsp = eregmatch(pattern:"form:(j_id_jsp_[^' ;]+)", string:buf);

    if(!isnull(j_id_jsp[1])) {

      c = eregmatch(pattern:"Set-Cookie: JSESSIONID=([^;]+);",string:buf);

      if(!isnull(c[1])) {

        j_id = urlencode(str:j_id_jsp[1]);
        variables = string("form%3Ausername=admin&form%3Apassword=admin&form%3Achangelang=EN&form_SUBMIT=1&javax.faces.ViewState=",st,"&form%3A_idcl=form%3A",j_id);

        req = string(
                "POST /login.jsf HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Referer: http://", host,"/login.jsf\r\n",
                "Cookie: JSESSIONID=",c[1],"\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", (strlen(variables)),
                "\r\n\r\n",
                variables
              );
        result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

        if("302 Moved" >< result && "/home.jsf" >< result) {

          security_message(port:port,data:string("The remote F-Secure Internet Gatekeeper uses default credentials (admin:admin).\nChange the default password as soon as possible\n"));

          req = string(
                      "GET /version.jsf HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "Referer: http://", host,"/home.jsf\r\n",
                      "Cookie: JSESSIONID=",c[1],"\r\n",
                      "\r\n\r\n"
                      );

          result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

          if("Product version" >< result && "System information" >< result) {
            version = eregmatch(pattern:'<td class="f12">([0-9.]+ build [0-9]+)', string:result);
            if(!isnull(version[1])) {
              vers = version[1];
            }
          }
        }
      }
    }
  }

  set_kb_item(name: string("www/", port, "/f_secure_internet_gatekeeper"), value: string(vers," under ",install));
  set_kb_item(name: "f_secure_internet_gatekeeper/detected", value: TRUE);

  if(vers == "unknown") {
    register_host_detail(name:"App", value:string("cpe:/a:f-secure:internet_gatekeeper:unknown::linux"), desc:SCRIPT_DESC);
  } else {
    register_host_detail(name:"App", value:string("cpe:/a:f-secure:internet_gatekeeper:",vers,"::linux"), desc:SCRIPT_DESC);
  }

  info = string("F-Secure Internet Gatekeeper Version '");
  info += string(vers);
  info += string("' was detected on the remote host\n");
  log_message(port:port, data:info);
}

exit(0);