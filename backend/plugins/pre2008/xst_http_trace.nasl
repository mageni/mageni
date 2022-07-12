###############################################################################
# OpenVAS Vulnerability Test
# $Id: xst_http_trace.nasl 10828 2018-08-08 07:56:38Z cfischer $
#
# HTTP Debugging Methods (TRACE/TRACK) Enabled
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2003 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11213");
  script_version("$Revision: 10828 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 09:56:38 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("HTTP Debugging Methods (TRACE/TRACK) Enabled");
  script_cve_id("CVE-2003-1567", "CVE-2004-2320", "CVE-2004-2763", "CVE-2005-3398", "CVE-2006-4683",
                "CVE-2007-3008", "CVE-2008-7253", "CVE-2009-2823", "CVE-2010-0386", "CVE-2012-2223",
                "CVE-2014-7883");
  script_bugtraq_id(9506, 9561, 11604, 15222, 19915, 24456, 33374, 36956, 36990, 37995);
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 E-Soft Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/288308");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/867593");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/current/de/mod/core.html#traceenable");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Cross_Site_Tracing");

  script_tag(name:"summary", value:"Debugging functions are enabled on the remote web server.

  The remote web server supports the TRACE and/or TRACK methods. TRACE and TRACK
  are HTTP methods which are used to debug web server connections.");

  script_tag(name:"insight", value:"It has been shown that web servers supporting this methods are
  subject to cross-site-scripting attacks, dubbed XST for Cross-Site-Tracing, when used in
  conjunction with various weaknesses in browsers.");

  script_tag(name:"impact", value:"An attacker may use this flaw to trick your legitimate web users to give
  him their credentials.");

  script_tag(name:"affected", value:"Web servers with enabled TRACE and/or TRACK methods.");

  script_tag(name:"solution", value:"Disable the TRACE and TRACK methods in your web server configuration.

  Please see the manual of your web server or the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

report = "The web server has the following HTTP methods enabled:";
file   = "/OpenVAS" + rand() + ".html"; # Does not exist
cmd1   = http_get( item:file, port:port );
cmd2   = cmd1;
cmd1   = ereg_replace( pattern:"GET /", string:cmd1, replace:"TRACE /" );
cmd2   = ereg_replace( pattern:"GET /", string:cmd2, replace:"TRACK /" );
ua     = egrep( pattern:"^User-Agent", string:cmd1 );

res = http_keepalive_send_recv( port:port, data:cmd1, bodyonly:TRUE );
if( res ) {
  if( egrep( pattern:"^TRACE " + file + " HTTP/1\.", string:res ) ) {
    if( ! ua || ( ua && ua >< res ) ) {
      VULN = TRUE;
      report += " TRACE";
      expert_info += 'Request:\n' + cmd1;
      expert_info += 'Response (Body):\n' + res;
    }
  }
}

res = http_keepalive_send_recv( port:port, data:cmd2, bodyonly:TRUE );
if( res ) {
  if( egrep( pattern:"^TRACK " + file + " HTTP/1\.", string:res ) ) {
    if( ! ua || ( ua && ua >< res ) ) {
      VULN = TRUE;
      report += " TRACK";
      expert_info += 'Request:\n' + cmd2;
      expert_info += 'Response (Body):\n' + res;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );