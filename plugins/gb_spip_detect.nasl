###############################################################################
# OpenVAS Vulnerability Test
#
# SPIP Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103776");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-04-16T11:02:09+0000");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"2019-04-16 11:02:09 +0000 (Tue, 16 Apr 2019)");
  script_tag(name:"creation_date", value:"2013-08-29 11:47:51 +0200 (Thu, 29 Aug 2013)");

  script_name("SPIP Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.spip.net");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/spip", cgi_dirs( port:port ) ) ) {
  install = dir;
  if (dir == "/") dir = "";

  url = dir + '/spip.php';
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if ("Composed-By: SPIP" >< buf) {
    vers = 'unknown';

    version = eregmatch(pattern:"Composed-By: SPIP ([0-9a-z.]+)", string:buf);
    if (isnull(version[1]))
      version = eregmatch(pattern:'meta name="generator" content="SPIP ([0-9a-z]+)', string:buf);

    if(!isnull(version[1]))
      vers = version[1];

    set_kb_item(name:"spip/detected",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9a-z.]+)", base:"cpe:/a:spip:spip:");
    if (!cpe)
      cpe = 'cpe:/a:spip:spip';

    register_product(cpe:cpe, location:install, port:port);

    log_message(data: build_detection_report(app:"SPIP", version:vers, install:install, cpe:cpe,
                                             concluded: version[0]),
                port:port);
  }
}

exit(0);
