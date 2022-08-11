###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_info_disc_vuln_dec13.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# MediaWiki Information Disclosure Vulnerabilities-Dec13
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804166");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(62215, 62434);
  script_cve_id("CVE-2013-4302", "CVE-2013-4301");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 09:57:37 +0530 (Tue, 17 Dec 2013)");
  script_name("MediaWiki Information Disclosure Vulnerabilities-Dec13");

  script_tag(name:"summary", value:"The host is running MediaWiki and is prone to information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not.");

  script_tag(name:"solution", value:"Upgrade to MediaWiki Version 1.19.8 or 1.20.7 or 1.21.2 or later.");

  script_tag(name:"insight", value:"The flaws are due to,

  - An error within the 'tokens', 'unblock', 'login', 'createaccount', and
  'block' API calls can be exploited to disclose the CSRF token value.

  - The application discloses the full installation path in an error message
   when an invalid language is specified in ResourceLoader to 'load.php'
   script.");

  script_tag(name:"affected", value:"MediaWiki version 1.19.x before 1.19.8, 1.20.x before 1.20.7 and 1.21.x
  before 1.21.2");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain CSRF tokens,
  bypass the cross-site request forgery (CSRF) protection mechanism and gain
  knowledge on sensitive directories on the remote web server via requests.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54715");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/553");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86896");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=49090");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=46332");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!mwPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:mwPort)){
  exit(0);
}

if( dir == "/" ) dir = "";

req = http_post_req( port:mwPort,
                     url:dir + '/api.php',
                     data:'action=login&lgname=User1&lgpassword=xxx&format=json&callback=OpenVAS',
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" )
                   );

buf = http_keepalive_send_recv( port:mwPort, data:req, bodyonly:FALSE );

if( token = eregmatch( pattern:'OpenVAS\\(\\{"login":\\{"result":"NeedToken","token":"([a-f0-9]+)"', string: buf ) )
{
  if( isnull( token[1] ) ) exit( 99 );
  security_message(port:mwPort, data:'It was possible to get the csrf token `' + token[1] + '` via a jsonp request.');
  exit(0);
}

exit( 99 );
