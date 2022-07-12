###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seportal_sql_inj_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# SePortal poll.php SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800143");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-5191");
  script_bugtraq_id(29996);
  script_name("SePortal poll.php SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30865");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5960");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary SQL queries.");
  script_tag(name:"affected", value:"SePortal Version 2.4 and prior on all running platform.");
  script_tag(name:"insight", value:"Input passed to the poll_id parameter in poll.php and to sp_id parameter
  in staticpages.php files are not properly sanitised before being used in an SQL query.");
  script_tag(name:"solution", value:"Upgrade to SePortal Version 2.5 or later");
  script_tag(name:"summary", value:"The host is running SePortal which is prone to SQL Injection
  Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/seportal", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir + "/index.php"), port:port);
  if(!rcvRes) continue;

  if("SePortal<" >< rcvRes)
  {
    sepVer = eregmatch(string:rcvRes, pattern:"SePortal<.+ ([0-9]\.[0-9.]+)");
    if(sepVer[1] != NULL)
    {
      if(version_is_less_equal(version:sepVer[1], test_version:"2.4")){
        security_message(port:port);
      }
    }
    exit(0);
  }
}

exit(99);