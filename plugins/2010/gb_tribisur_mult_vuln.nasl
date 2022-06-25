##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tribisur_mult_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Tribisur Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800740");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0958");
  script_bugtraq_id(38596);
  script_name("Tribisur Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28362");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11655");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1003-exploits/tribisur-lfi.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input passed to the 'theme' parameter in 'modules/hayoo/index.php' is not
  properly verified before being used to include files.

  - An Input passed to the 'id' parameter in 'cat_main.php', and other parameters
  is not properly sanitised before being used in SQL queries.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Tribisur and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information and execute arbitrary local scripts in the context of an affected site.");
  script_tag(name:"affected", value:"Tribisur version 2.1 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

triPort = get_http_port(default:80);


if(!can_host_php(port:triPort)){
  exit(0);
}

foreach dir (make_list_unique("/Tribisur", "/tribisur", "/", cgi_dirs(port:triPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/scripts.php", port:triPort);

  if("TRIBISUR" >< rcvRes)
  {
    triVer = eregmatch(pattern:" //v([0-9.]+)", string:rcvRes);
    if(triVer[1] != NULL)
    {
      if(version_is_less_equal(version:triVer[1], test_version:"2.1")){
        security_message(port:triPort);
        exit(0);
      }
    }
  }
}

exit(99);