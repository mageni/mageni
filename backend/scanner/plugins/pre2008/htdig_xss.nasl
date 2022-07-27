###############################################################################
# OpenVAS Vulnerability Test
# $Id: htdig_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# ht://Dig htsearch.cgi XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: Howard Yeend <h_bugtraq@yahoo.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15706");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2010");
  script_bugtraq_id(5091);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ht://Dig htsearch.cgi XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to a newer when available");
  script_tag(name:"summary", value:"The 'htsearch' CGI, which is part of the ht://Dig package,
  is vulnerable to cross-site scripting attacks,
  through 'words' variable.

  With a specially crafted URL, an attacker can cause arbitrary
  code execution resulting in a loss of integrity.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/htsearch.cgi?words=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E" );

  if( http_vuln_check( port:port, url:url, pattern:"<script>foo</script>" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
