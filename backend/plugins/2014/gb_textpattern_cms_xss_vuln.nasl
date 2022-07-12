###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_textpattern_cms_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Textpattern 'index.php' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804499");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4737");
  script_bugtraq_id(70203);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-16 16:06:39 +0530 (Thu, 16 Oct 2014)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_name("Textpattern 'index.php' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Textpattern
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  sanitization of input data passed via URI after '/textpattern/setup/index.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Textpattern version 4.5.5 and probably prior");

  script_tag(name:"solution", value:"Upgrade Textpattern 4.5.7 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/96802");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23223");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128519/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533596/100/0/threaded");
  script_xref(name:"URL", value:"http://textpattern.com/weblog/379/textpattern-cms-457-released-ten-years-on");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

serPort = get_http_port(default:80);

if(!can_host_php(port:serPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/textpattern", "/cms", cgi_dirs(port:serPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:serPort);

  if(">Textpattern<" >< res && "Textpattern CMS<" >< res)
  {
    url = dir + '/setup/index.php/"><script>alert(document.cookie);</script>/index.php';

    if(http_vuln_check(port:serPort, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\);</script>",
                extra_check: ">Welcome to Textpattern<"))
    {
      security_message(port:serPort);
      exit(0);
    }
  }
}

exit(99);