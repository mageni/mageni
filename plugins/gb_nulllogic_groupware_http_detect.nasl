# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800905");
  script_version("2021-03-19T12:24:39+0000");
  script_tag(name:"last_modification", value:"2021-03-19 12:24:39 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NullLogic Groupware Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 4110);
  script_mandatory_keys("NullLogic_Groupware/banner");

  script_tag(name:"summary", value:"HTTP based detection of NullLogic Groupware.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:4110);
banner = http_get_remote_headers(port:port);
if(!banner || !concl = egrep(string:banner, pattern:"NullLogic Groupware", icase:FALSE))
  exit(0);

install = "/";
concl = chomp(concl);
version = "unknown";

vers = eregmatch(pattern:"NullLogic Groupware ([0-9.]+)", string:concl);
if(vers[1])
  version = vers[1];

set_kb_item(name:"nulllogic/groupware/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:nulllogic:groupware:");
if(!cpe)
  cpe = "cpe:/a:nulllogic:groupware";

register_product(cpe:cpe, location:install, port:port, service:"www");
log_message(data:build_detection_report(app:"NullLogic Groupware",
                                        version:version,
                                        install:install,
                                        cpe:cpe,
                                        concluded:concl),
            port:port);

exit(0);