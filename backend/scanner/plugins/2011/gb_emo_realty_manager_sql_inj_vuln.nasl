###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emo_realty_manager_sql_inj_vuln.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# EMO Realty Manager 'cat1' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802342");
  script_version("$Revision: 12010 $");
  script_bugtraq_id(40625);
  script_cve_id("CVE-2010-5006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 16:19:55 +0530 (Wed, 09 Nov 2011)");
  script_name("EMO Realty Manager 'cat1' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8505");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/90411/emorealtymanager-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  injection attack and gain sensitive information.");
  script_tag(name:"affected", value:"EMO Realty Manager Software.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via the 'cat1' parameter to 'googlemap/index.php', which allows attackers
  to manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running EMO Realty Manager Software and is prone to
  SQL injection vulnerability");

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

foreach dir(make_list_unique("/emo_virtual", "/emorealty", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('<title>EMO Realty Manager' >< res)
  {
    url = string(dir, "/googlemap/index.php?cat1='");

    if(http_vuln_check(port:port, url:url, pattern:'You have an error' +
                      ' in your SQL syntax;', check_header: FALSE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);