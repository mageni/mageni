###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zencart_database_backup_disclosure_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Zen-cart Database Backup Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804179");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-27 13:57:37 +0530 (Fri, 27 Dec 2013)");
  script_name("Zen-cart Database Backup Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is running Zen-cart and is prone to database backup disclosure
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"insight", value:"The flaw is due to unspecified error that allows unauthenticated access to
  database backup");
  script_tag(name:"affected", value:"Zen-cart version 1.5.1 and probably prior");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  database information by downloading the database backup.");

  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120167");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/zen-cart-database-backup-disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

zcPort = get_http_port(default:80);

if(!can_host_php(port:zcPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/zencart", "/zen-cart", "/cart", cgi_dirs(port:zcPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:zcPort);

  if(res && (egrep(pattern:"Powered by.*Zen Cart<", string:res)))
  {
    url = dir + '/zc_install/sql/mysql_zencart.sql';

    if(http_vuln_check(port:zcPort, url:url, pattern:'Zen Cart SQL Load',
      extra_check:make_list('customers_id','admin_name')))
    {
      security_message(port:zcPort);
      exit(0);
    }
  }
}

exit(99);
