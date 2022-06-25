###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_ng_mult_xss_sql_vul.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# OCS Inventory NG Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801204");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_bugtraq_id(38131);
  script_cve_id("CVE-2010-1594", "CVE-2010-1595");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OCS Inventory NG Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38311");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1001-exploits/ocsinventoryng-sqlxss.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject arbitrary web script
  or HTML and conduct Cross-Site Scripting attacks.");
  script_tag(name:"affected", value:"OCS Inventory NG 1.02.1 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - improper validation of user-supplied input via 1)the query string,
    (2)the BASE parameter, or (3)the ega_1 parameter in ocsreports/index.php.
   that allow remote attackers to inject arbitrary web script or HTML.

  - improper validation of user-supplied input via (1)c, (2)val_1, or
    (3)onglet_bis parameter in ocsreports/index.php that allow remote attackers
    to execute arbitrary SQL commands.");
  script_tag(name:"solution", value:"Upgrade to the latest version of OCS Inventory NG 1.02.3 or later.");
  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is prone to multiple
  cross-site scripting and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ocsinventory");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/ocsreports", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">OCS Inventory<" >< res)
  {
    ver = eregmatch(pattern:"Ver.? ?([0-9.]+).?", string:res);

    if(ver[1])
    {
      if(version_in_range(version:ver[1], test_version:"1.02",
                                          test_version2:"1.02.1"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);