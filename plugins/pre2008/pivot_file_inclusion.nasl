# OpenVAS Vulnerability Test
# $Id: pivot_file_inclusion.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: File Inclusion Vulnerability in Pivot
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
#

# From: loofus@0x90.org - loofus
# Subject: Pivot Remote Code Execution Vulnerability
# Date: 2004-06-17
#
# changes by rd: description and detection method
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12282");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("File Inclusion Vulnerability in Pivot");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Pivot 1.14.1 or disable this CGI altogether");
  script_tag(name:"summary", value:"Pivot is a set of PHP scripts designed to maintain dynamic web pages.

  There is a flaw in the file module_db.php which may let an attacker execute
  arbitrary commands on the remote host by forcing the remote Pivot installation
  to include a PHP file hosted on an arbitrary third-party website.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{

 if(path == "/") path = "";

 req = http_get(item:string(path, "/modules/module_db.php?pivot_path=http://xxxxxxxxxx/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "http://xxxxxxxxxx/modules/module_db_xml.php" >< res )
 {
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/pivot", cgi_dirs(port:port))) check_dir(path:dir);

exit(99);