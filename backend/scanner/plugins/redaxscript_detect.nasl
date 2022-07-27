###############################################################################
# OpenVAS Vulnerability Test
# $Id: redaxscript_detect.nasl 13902 2019-02-27 10:31:50Z cfischer $
#
# Redaxscript Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100121");
  script_version("$Revision: 13902 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 11:31:50 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Redaxscript Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://redaxscript.com/");

  script_tag(name:"summary", value:"This host is running Redaxscript a free, PHP and MySQL driven
  Content Management System for small business and private websites.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit(0);

foreach dir( make_list_unique( "/redaxscript", "/cms", "/php", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/", port:port );
  if(!buf)
    continue;

  if( '"generator" content="Redaxscript' >< buf && 'Content could not be found.</p>' >!< buf ) {

    vers = "unknown";
    version = eregmatch(string:buf, pattern:'"generator" content="Redaxscript ([0-9.]+)"', icase:TRUE);

    if(version[1])
      vers = version[1];

    set_kb_item(name:"redaxscript/detected", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:redaxscript:redaxscript:");
    if(!cpe)
      cpe = "cpe:/a:redaxscript:redaxscript";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Redaxscript",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0]),
                                            port:port);
  }
}

exit(0);