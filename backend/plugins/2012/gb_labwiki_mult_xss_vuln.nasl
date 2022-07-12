##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_labwiki_mult_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# LabWiki Multiple Cross Site Scripting (XSS) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802956");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-27 16:52:41 +0530 (Mon, 27 Aug 2012)");
  script_name("LabWiki Multiple Cross Site Scripting (XSS) Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/523960");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Aug/262");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115801/LabWiki-1.5-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed to the 'from' parameter in index.php and to the
  'page_no' parameter in recentchanges.php is not properly sanitised before being
  returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running LabWiki and is prone to multiple cross site
  scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an
  affected website.");
  script_tag(name:"affected", value:"LabWiki version 1.2.1 and prior");

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

foreach dir (make_list_unique("/", "/wiki", "/labwiki", "/LabWiki", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(rcvRes && '>My Lab</a' >< rcvRes && '>What is Wiki</' >< rcvRes)
  {
    url = string(dir, '/recentchanges.php?page_no="><script>alert(document.cookie)</script>');

    if(http_vuln_check(port:port, url:url, pattern:"><script>alert" +
                       "\(document\.cookie\)</script>", check_header:TRUE,
                        extra_check:">What is Wiki<"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
