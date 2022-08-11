###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_balero_cms_mul_vul.nasl 2015-04-09 13:05:47 +0530 Apr$
#
# Balero CMS Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805365");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-04-09 13:05:47 +0530 (Thu, 09 Apr 2015)");
  script_name("Balero CMS Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36675");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36676");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2015-5239.php");

  script_tag(name:"summary", value:"The host is installed with Balero CMS
  and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP
  GET and check whether it is able to read cookie or not.");
  script_tag(name:"insight", value:"Multiple flaws are due to input
  passed via,

  - 'content' parameter to 'mod-blog' is not properly validated.

  - 'counter' parameter to 'admin' is not properly validated.

  - 'pages' and 'themes' parameter to 'admin' is not properly validated.

  - 'a' and 'virtual_title' parameter to 'mod-virtual_page' is not properly validated.

  - 'id' and 'title' parameter to 'mod-blog' is not properly validated.

  - 'code' parameter to 'mod-languages' is not properly validated.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database and execute
  arbitrary HTML and script code in a users browser session in the context of an
  affected site.");
  script_tag(name:"affected", value:"Balero CMS version 0.7.2, Prior
  versions may also be affected.");
  script_tag(name:"solution", value:"Update to Balero CMS 0.8.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.balerocms.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

# start script
port = get_http_port( default:80 );

host = http_host_name( port:port );

useragent = http_get_user_agent();

foreach dir( make_list_unique( "/", "/balerocms", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/", port:port );

  if( ">Balero CMS<" >< rcvRes ) {

    url = dir + '/admin';
    cookie = '<script>alert("XSS")</script>';
    postdata = string("usr=aqsd&pwd=asd&login=Log+In\r\n");

    sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                     'Host: ', host, '\r\n',
                     'User-Agent: ', useragent, 'r\n',
                     'Referer: http://', host, url,'\r\n',
                     'Cookie: counter=', cookie,'\r\n',
                     'Content-Type: application/x-www-form-urlencoded\r\n',
                     'Content-Length: ', strlen(postdata), '\r\n\r\n',
                      postdata);
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if(rcvRes =~ "HTTP/1\.. 200" && 'alert("XSS")' >< rcvRes && rcvRes && '>Login<' >< rcvRes ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
