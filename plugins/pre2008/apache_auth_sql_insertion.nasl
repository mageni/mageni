# OpenVAS Vulnerability Test
# $Id: apache_auth_sql_insertion.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: Apache Auth Module SQL Insertion Attack
#
# Authors:
# 2001 Matt Moore <matt@westpoint.ltd.uk>
# modifications by rd : use of regexps
#
# Copyright:
# Copyright (C) 2001 Matt Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Script to check for Apache Authentication Modules SQL Insertion Vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10752");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3251, 3253);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1379");

  script_name("Apache Auth Module SQL Insertion Attack");




  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("This script is Copyright (c) 2001 Matt Moore");
  script_family("General");

  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/apache");
  script_tag(name:"solution", value:"Upgrade the module");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This plugin checks whether the web server is
  using Apache Auth modules which are known to be vulnerable to SQL
  insertion attacks.");
  exit(0);
}

#
# Script code begins...
#

include("http_func.inc");

 port = get_http_port(default:80);


 banner = get_http_banner(port: port);



  report =
string("There is a vulnerable version of the NAME module installed on this\n",
"Apache Web Server.\n",
"This module is vulnerable to a SQL insertion attack that could allow an\n",
"attacker to execute arbitrary SQL statements.\n\n",
"Solution: Get the latest version of this module (probably VERSION) at URL\n\n",
"References: RUS CERT Advisory available at http://cert-uni-stuttgart.de/advisories/apache_auth.php");

# Now check whether the banner contains references to the vulnerable modules...

  if (egrep(pattern:"^Server:.*mod_auth_pg/((0\.[0-9])|(1\.[0-1])|1\.2b[0-2])([^0-9]|$)", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pg\31.3\5http://authpg.sourceforge.net\7",
			 string:report);

   security_message(port:port, data:r);
   exit(0);
  }


  if (egrep(pattern:"^Server:.*mod_auth_mysql/((0\.[0-9])|(1\.[0-9]))([^0-9]|$)", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_mysql\31.10\5ftp://ftp.kcilink.com/pub/\7",
			 string:report);

   security_message(port:port, data:r);
  }

  if (egrep(pattern:"^Server:.*mod_auth_oracle/0\.([0-4].*|5\.[0-1]([^0-9]|$))", string:banner))
  {
    r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_oracle\30.5.2\5some place\7",
			 string:report);


   security_message(port:port, data:r);
  }

  if (egrep(pattern:"^Server:.*mod_auth_pgsql/0\.(([0-8]\..*)|(9\.[0-5]([^0-9]|$))).*", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pgsql\30.9.6\5http://www.giuseppetanzilli.it/mod_auth_pgsql/dist\7",
			 string:report);


   security_message(port:port, data:r);
  }


  if (egrep(pattern:"^Server:.*mod_auth_pgsql_sys/0\.(([0-8]\..*)|(9\.[0-4]([^0-9]|$))).*", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pgsql_sys\30.9.5\5some place\7",
			 string:report);


   security_message(port:port, data:r);
}
