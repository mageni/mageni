###############################################################################
# OpenVAS Vulnerability Test
#
# MacOS X Finder '.FBCIndex' Information Disclosure
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Modified by Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2001 Matt Moore, Modified by Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.10773");
  script_version("2019-04-24T07:26:10+0000");
  script_cve_id("CVE-2001-1446");
  script_bugtraq_id(3325);
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MacOS X Finder '.FBCIndex' Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Matt Moore, Modified by Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/3325");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/177243");

  script_tag(name:"solution", value:"Block access to hidden files (starting with a dot) within your webservers
  configuration");

  script_tag(name:"summary", value:"MacOS X creates a hidden file, '.FBCIndex' in each directory that has been
  viewed with the Finder. This file contains the content of the files present
  in the directory, giving an attacker information on the HTML tags, JavaScript,
  passwords, or any other sensitive word used inside those files.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

report = 'The following files were identified:\n';

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/.FBCIndex";
  res = http_get_cache( port:port, item:url );
  if( res =~ "^HTTP/1\.[01] 200" && "Bud2" >< res ) {
    report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
    found   = TRUE;
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );