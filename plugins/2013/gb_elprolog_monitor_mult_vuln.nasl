###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elprolog_monitor_mult_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Elprolog Monitor WebAccess Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804113");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(62631);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-22 12:55:00 +0530 (Tue, 22 Oct 2013)");
  script_name("Elprolog Monitor WebAccess Multiple Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute/inject own
  SQL commands in the vulnerable web-application database management system
  and force the client side browser requests with manipulated web application
  context or cross site links.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'data' parameter to sensorview.php and via the 'name'
  parameter to strend.php is not properly sanitised before being returned to
  the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Elprolog Monitor WebAccess and is prone to multiple
  vulnerabilities.");
  script_tag(name:"affected", value:"Elprolog Monitor Webaccess 2.1, Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62631");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123496");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/elprolog-monitor-webaccess-21-xss-sql-injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/elpro-demo", "/webaccess", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

   req = http_get(item:string(dir, "/sensorview.php"),  port: http_port);
   res = http_keepalive_send_recv(port:http_port, data:req);

   if(res && ">elproLOG MONITOR-WebAccess<" >< res)
   {

     url = dir + '/sensorview.php?data=ECOLOG-NET Testing' +
           '-<script>alert(document.cookie);</script>';

     if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\);</script>" ,
       extra_check:"ECOLOG-NET"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
