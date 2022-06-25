###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_continuum_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Apache Continuum Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

  script_oid("1.3.6.1.4.1.25623.1.0.103073");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-11 13:54:50 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Continuum Detection");

  script_tag(name:"summary", value:"Detection of Apache Continuum

The script sends a connection request to the server and attempts to detect the presence of Apache Continuum and to
extract its version");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://continuum.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

url = string("/continuum/about.action");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if( buf == NULL )continue;
buf_lines = split(buf);

if("Continuum - About" >< buf && "<h3>About Continuum</h3>" >< buf)
{
  install = string("/continuum");
  version = string("unknown");

  x=0;
  foreach line (buf_lines) {
    x++;

    if("Version:</label>" >< line) {
      vers = eregmatch(string: buf_lines[x], pattern: "([0-9.]+)</td>",icase:TRUE);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "apache_continuum/version", value: version);
      }
    }

    if("Build Number:</label>" >< line) {
      b = eregmatch(string: buf_lines[x], pattern: "([0-9]+)</td>",icase:TRUE);
      if (!isnull(b[1])) {
        build = b[1];
        set_kb_item(name: "apache_continuum/build", value: build);
      }
      break;
    }
  }

  set_kb_item(name: "apache_continuum/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:continuum:");
  if (!cpe)
    cpe = 'cpe:/a:apache:continuum';

  register_product(cpe: cpe, location: install, port: port);

  log_message(data: build_detection_report(app: "Apache Continuum", version: version + " Build: " + build,
                                           install: install, cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);

