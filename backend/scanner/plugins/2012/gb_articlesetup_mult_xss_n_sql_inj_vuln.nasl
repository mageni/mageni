###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_articlesetup_mult_xss_n_sql_inj_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# ArticleSetup Multiple Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802427");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(52834);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-04 11:17:27 +0530 (Wed, 04 Apr 2012)");
  script_name("ArticleSetup Multiple Cross-Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=497");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18682/");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_ArticleSetup_Multiple_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of
  an affected site and manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"ArticleSetup version 1.11 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed to 'userid' and 'password' parameter in '/upload/login.php'
  and '/upload/admin/login.php' page is not properly verified before being used.

  - Input passed to the 'cat' parameter in 'upload/feed.php', 's' parameter in
  'upload/search.php', 'id' parameter in '/upload/admin/pageedit.php',
  'upload/admin/authoredit.php' and '/admin/categoryedit.php' pages are  not
  properly verified before being used.

  - Input passed to the 'title' parameter in 'upload//author/submit.php',
  '/upload/admin/articlenew.php', '/upload/admin/categories.php' and
  '/upload/admin/pages.php' pages are not properly verified before being used.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running ArticleSetup and is prone to multiple
  cross-site scripting and SQL injection vulnerabilities.");

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

foreach dir (make_list_unique("/", "/ArticleSetup", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  if(http_vuln_check(port:port, url: dir + "/upload/index.php", pattern:">Art" +
     "icle Script</", extra_check: make_list(">Most Viewed","All Categories<",
     ">Submit Articles<")))
  {
    exploits = make_list("/upload/search.php?s='",
                         "/upload/search.php?s=<script>alert(document.cookie)</script>");

    foreach exploit(exploits)
    {
      if(http_vuln_check(port:port, url: dir + exploit,
         pattern:"You have an error in your SQL syntax;|<script>alert\(docum" +
         "ent.cookie\)</script>", extra_check:make_list(">Submit Articles<", "All" +
         " Categories<"), check_header:TRUE))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
