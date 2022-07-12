###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Sambar XSS
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
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

# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80083");
  script_version("$Revision: 13679 $");
  script_cve_id("CVE-2003-1284", "CVE-2003-1285");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(7209);
  script_name("Sambar XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  script_tag(name:"solution", value:"Delete these CGIs.");

  script_tag(name:"summary", value:"The Sambar web server comes with a set of CGIs that are vulnerable
  to a cross-site scripting attack.");

  script_tag(name:"impact", value:"An attacker may use this flaw to steal the cookies of your web users.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

cgis = make_list(
  "/netutils/ipdata.stm?ipaddr=",
  "/netutils/whodata.stm?sitename=",
  "/netutils/finddata.stm?user=",
  "/isapi/testisa.dll?check1=",
  "/cgi-bin/environ.pl?param1=",
  "/samples/search.dll?logic=AND&query=",
  "/wwwping/index.stm?wwwsite=",
  "/syshelp/stmex.stm?bar=456&foo=",
  "/syshelp/cscript/showfunc.stm?func=",
  "/syshelp/cscript/showfncs.stm?pkg=",
  "/syshelp/cscript/showfnc.stm?pkg=",
  "/sysuser/docmgr/ieedit.stm?path=",
  "/sysuser/docmgr/edit.stm?path=",
  "/sysuser/docmgr/iecreate.stm?path=",
  "/sysuser/docmgr/create.stm?path=",
  "/sysuser/docmgr/info.stm?path=",
  "/sysuser/docmgr/ftp.stm?path=",
  "/sysuser/docmgr/htaccess.stm?path=",
  "/sysuser/docmgr/mkdir.stm?path=",
  "/sysuser/docmgr/rename.stm?path=",
  "/sysuser/docmgr/search.stm?path=",
  "/sysuser/docmgr/sendmail.stm?path=",
  "/sysuser/docmgr/template.stm?path=",
  "/sysuser/docmgr/update.stm?path=",
  "/sysuser/docmgr/vccheckin.stm?path=",
  "/sysuser/docmgr/vccreate.stm?path=",
  "/sysuser/docmgr/vchist.stm?path=",
  "/cgi-bin/testcgi.exe?" );

tmpReport = NULL;

foreach cgi( cgis ) {

  url = cgi + "<script>foo</script>";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< res ) {
    tmpReport += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }
}

if( ! isnull( tmpReport ) ) {
  report = "The following Sambar default CGIs are vulnerable to a cross-site scripting attack:";
  report += '\n\n' + tmpReport;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
