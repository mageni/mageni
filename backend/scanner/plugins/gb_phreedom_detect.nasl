###############################################################################
# OpenVAS Vulnerability Test
#
# Phreedom Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103098");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-05-06T06:57:16+0000");
  script_tag(name:"last_modification", value:"2020-05-07 10:48:07 +0000 (Thu, 07 May 2020)");
  script_tag(name:"creation_date", value:"2011-03-01 13:10:12 +0100 (Tue, 01 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Phreedom Detection");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Phreedom, an Enterprise Resource Planning System
made for small and medium sized business.");
  script_xref(name:"URL", value:"http://www.phreesoft.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/phreedom", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( egrep( pattern:"<title>Phreedom ERP</title>", string:buf, icase:TRUE ) )  {

    vers = string("unknown");

    set_kb_item(name: string("www/", port, "/Phreedom"), value: string(vers," under ",install));

    info = string("Phreedom Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit( 0 );
