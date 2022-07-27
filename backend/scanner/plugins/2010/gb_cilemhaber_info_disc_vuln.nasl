###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cilemhaber_info_disc_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Cilem Haber Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801605");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Cilem Haber Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62249");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15199/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download
  the database and obtain sensitive information.");

  script_tag(name:"affected", value:"Cilem Haber Version 1.4.4");

  script_tag(name:"insight", value:"The flaw is caused by improper restrictions on the
  'cilemhaber.mdb' database file. By sending a direct request, a remote attacker
  could download the database and obtain sensitive information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Cilem Haber and is prone to information
  disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cilemhaber", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/www/default.asp", port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "HTTP/1.[0-1] 200" && "cilemhaber" >< res ) {

    url = dir + "/db/cilemhaber.mdb";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "HTTP/1.[0-1] 200" && 'Standard Jet DB' >< res ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );