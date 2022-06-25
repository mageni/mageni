###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eticket_pri_para_mult_sql_inj_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# eTicket pri Parameter Multiple SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.800141");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5165");
  script_bugtraq_id(29973);
  script_name("eTicket pri Parameter Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30877");
  script_xref(name:"URL", value:"http://www.eticketsupport.com/announcements/170_is_in_the_building-t91.0.html");
  script_xref(name:"URL", value:"http://www.digitrustgroup.com/advisories/web-application-security-eticket2.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could allow manipulation of the database by injecting
  arbitrary SQL queries.");
  script_tag(name:"affected", value:"eTicket Version 1.5.7 and prior.");
  script_tag(name:"insight", value:"Input passed to the pri parameter of index.php, open.php, open_raw.php, and
  newticket.php is not properly sanitised before being used in SQL queries.");
  script_tag(name:"solution", value:"Update to Version 1.7.0 or later.");
  script_tag(name:"summary", value:"The host is running eTicket, which is prone to multiple SQL Injection
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/eTicket", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/license.txt", port:port);
  if(rcvRes && rcvRes =~ "^HTTP/1\.[01] 200" && "eTicket" >< rcvRes)
  {
    eTicVer = eregmatch(pattern:"eTicket ([0-9.]+)", string:rcvRes);
    if(eTicVer[1] != NULL)
    {
      if(version_is_less_equal(version:eTicVer[1], test_version:"1.5.7")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);