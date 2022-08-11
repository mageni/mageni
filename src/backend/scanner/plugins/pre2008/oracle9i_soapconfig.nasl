###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle9i_soapconfig.nasl 9328 2018-04-05 11:14:07Z cfischer $
#
# Oracle 9iAS SOAP configuration file retrieval
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
  script_oid("1.3.6.1.4.1.25623.1.0.11224");
  script_version("$Revision: 9328 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 13:14:07 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4290);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0568");
  script_name("Oracle 9iAS SOAP configuration file retrieval");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/OracleApache");

  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-08.html");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/476619");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");

  script_tag(name:"solution", value:"Modify the file permissions so that the web server process
  cannot retrieve it. Note however that if the XSQLServlet is present
  it might bypass filesystem restrictions.");

  script_tag(name:"summary", value:"In a default installation of Oracle 9iAS v.1.0.2.2.1, it is possible to
  access some configuration files. These file includes detailed
  information on how the product was installed in the server
  including where the SOAP provider and service manager are located
  as well as administrative URLs to access them. They might also
  contain sensitive information (usernames and passwords for database
  access).");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

# Note: this plugin can be expanded, I removed the call to
# SQLConfig since it's already done directly in #10855
configs = make_list( "/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml" );

# "/xsql/lib/XSQLConfig.xml"; # Already done by plugin #10855

VULN   = FALSE;
report = 'The following SOAP configuration files can be accessed directly:\n';

foreach config( configs  ) {

  req = http_get( item:config, port:port );
  r = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( isnull( r ) ) exit( 0 );

  if( "SOAP configuration file" >< r ) {
    report += '\n' + report_vuln_url( port:port, url:config, url_only:TRUE );
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );