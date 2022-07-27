###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle 9iAS OWA UTIL access
#
# Authors:
# Javier Fernandez-Sanguino <jfs@computer.org>
#
# Copyright:
# Copyright (C) 2003 Javier Fernandez-Sanguino
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11225");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4294);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0560");
  script_name("Oracle 9iAS OWA UTIL access");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/OracleApache");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/307835");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-08.html");
  script_xref(name:"URL", value:"http://otn.oracle.co.kr/docs/oracle78/was3x/was301/cart/psutil.htm");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");
  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/ias_modplsql_alert.pdf");

  script_tag(name:"summary", value:"Oracle 9iAS can provide access to the PL/SQL application OWA_UTIL that
  provides web access to some stored procedures.");

  script_tag(name:"impact", value:"These procuedures, without authentication, can allow users to access
  sensitive information such as source code of applications, user credentials to other
  database servers and run arbitrary SQL queries on servers accessed by the application
  server.");

  script_tag(name:"solution", value:"Apply the appropriate patch listed
  in the references.

  Details how you can restrict unauthenticated access to procedures
  using the exclusion_list parameter in the PL/SQL gateway configuration file:
  /Apache/modplsql/cfg/wdbsvr.app.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

# Make a request for the owa util file
owas = make_list(
# Note: sometimes access to this file seems to return 0 bytes
"/ows-bin/owa/owa_util.signature",

# The following mutations are derived from
# http://archives.neohapsis.com/archives/ntbugtraq/1999-q4/0023.html
# and might provide access to it in some cases were it has
# been prevented through authentication
"/ows-bin/owa/owa_util%2esignature",
"/ows-bin/owa/owa%5futil.signature",
"/ows-bin/owa/owa%5futil.signature",

# These are extracted from David Lichtfield's excellent paper:
"/ows-bin/owa/%20owa_util.signature",
"/ows-bin/owa/%0aowa_util.signature",
"/ows-bin/owa/%08owa_util.signature",

# These are some other procedures derived from the same mail
"/ows-bin/owa/owa_util.showsource",
"/ows-bin/owa/owa_util.cellsprint",
"/ows-bin/owa/owa_util.tableprint",
"/ows-bin/owa/owa_util.listprint",
"/ows-bin/owa/owa_util.show_query_columns" );

# Note that instead of ows-bin/owa any combination of
# pls/dadname could be used: pls/simpledad, pls/sys...

VULN   = FALSE;
report = 'Access to OWA_UTIL is possible through the following URLs:\n';

foreach owa( owas ) {
  req = http_get( item:owa, port:port );
  r = http_keepalive_send_recv( port:port, data:req );
  if( r == NULL ) exit( 0 );
  if( "This page was produced by the PL/SQL Web ToolKit" >< r || "DAD name:" >< r  || "PATH_INFO=/ows-bin/owa/" >< r ) {
    VULN = TRUE;
    report += '\n' + report_vuln_url( port:port, url:owa, url_only:TRUE );
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );