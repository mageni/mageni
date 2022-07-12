###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_mult_sql_inj_vuln.nasl 14332 2019-03-19 14:22:43Z asteins $
#
# OCS Inventory NG Multiple SQL Injection Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900938");
  script_version("$Revision: 14332 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3040");
  script_bugtraq_id(35152);
  script_name("OCS Inventory NG Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503936/100/0/threaded");
  script_xref(name:"URL", value:"http://www.leidecker.info/advisories/2009-05-30-ocs_inventory_ng_sql_injection.shtml");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject arbitrary SQL
  code and obtain sensitive information about system configurations and
  software on the network.");
  script_tag(name:"affected", value:"OCS Inventory NG version 1.02.");
  script_tag(name:"insight", value:"The user supplied input passedd into 'N', 'DL', 'O', 'v' parameters in
  download.php and 'systemid' parameter in group_show.php file is not
  sanitised before being used in an SQL query.");
  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is prone to multiple
  SQL Injection vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to version 1.02.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

ocsngPort = get_http_port(default:80);

if(!can_host_php(port:ocsngPort)){
  exit(0);
}

foreach dir (make_list_unique("/ocsreports", "/", cgi_dirs(port:ocsngPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/index.php", port:ocsngPort);

  if(("OCS Inventory" >< rcvRes) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    ocsVer = eregmatch(pattern:"Ver.? ?(([0-9.]+).?(RC[0-9]+)?)", string:rcvRes);
    if(!isnull(ocsVer[2]))
    {
      if(!isnull(ocsVer[3])){
        ocsVer = ocsVer[2] + "." + ocsVer[3];
      }
      else
        ocsVer = ocsVer[2];

      if((ocsVer != NULL) && version_is_equal(version:ocsVer, test_version:"1.02"))
      {
        security_message(port:ocsngPort, data:"The target host was found to be vulnerable.");
        exit(0);
      }
    }
  }
}

exit(99);
