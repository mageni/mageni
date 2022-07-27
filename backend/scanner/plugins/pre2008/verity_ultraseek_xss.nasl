###################################################################
# OpenVAS Vulnerability Test
# $Id: verity_ultraseek_xss.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# Verity Ultraseek search request XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
###################################################################

# Ref: Michael Krax

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17226");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12617);
  script_cve_id("CVE-2005-0514");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Verity Ultraseek search request XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8765);
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 5.3.3 or higher");
  script_tag(name:"summary", value:"The remote host runs Verity Ultraseek, an Enterprise Search Engine Software.

  This version is vulnerable to cross-site scripting and remote script injection due to a lack of sanitization of user-supplied data.");
  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to execute
  malicious script code on a vulnerable server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8765 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/help/copyright.html";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  #<h3>Verity Ultraseek 5.3.1</h3>
  if( "<title>About Verity Ultraseek</title>" >< res &&
      egrep( pattern:"Verify Ultraseek 5\.([23]\.[12]|3[^0-9])", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
