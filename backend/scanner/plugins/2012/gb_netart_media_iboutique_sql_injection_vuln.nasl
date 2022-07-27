##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netart_media_iboutique_sql_injection_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# NetArt Media iBoutique 'key' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802442");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-4039");
  script_bugtraq_id(54616);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-07-23 12:13:54 +0530 (Mon, 23 Jul 2012)");
  script_name("NetArt Media iBoutique 'key' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=510");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_NetArt_Media_iBoutique_SQLi_Vuln.txt");
  script_xref(name:"URL", value:"http://antusanadi.wordpress.com/2012/07/19/netart-media-iboutique-sql-injection-vulnerability/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed via the 'key' parameter to '/index.php' page is not
  properly verified before being used in a SQL query. This can be exploited to
  manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running NetArt Media iBoutique and is prone to
  SQL injection vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct SQL injection.");
  script_tag(name:"affected", value:"NetArt Media iBoutique version 4.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

ibPort = get_http_port(default:80);

if(!can_host_php(port:ibPort)){
  exit(0);
}

foreach dir (make_list_unique("/iboutique", "/", cgi_dirs(port:ibPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:ibPort);

  if(">Why iBoutique?</" >< rcvRes)
  {
    url = string(dir, "/index.php?mod=products&key=%27");

    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_message(port:ibPort);
      exit(0);
    }
  }
}

exit(99);