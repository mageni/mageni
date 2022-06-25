###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evolution_script_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Evolution Script CMS Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107218");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Evolution Script CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Evolution Script CMS.

  The script tries to detect the version of Evolution Script CMS remote host and sets the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port(default: 80);

foreach dir( make_list_unique( "/admin", cgi_dirs( port: appPort ) ) ) {

  install = dir;
  if (dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/" , port: appPort);

  if (rcvRes =~ "^HTTP/1\.[01] 200" && "<title>EvolutionScript - Login</title>" >< rcvRes ) {

    Ver = "unknown";

    tmpVer = eregmatch(pattern: "EvolutionScript ([0-9.]+) Admin Control Panel", string: rcvRes);

    if(tmpVer[1]) {
      Ver = tmpVer[1];
    }

    set_kb_item(name: "evolution_script/installed", value: TRUE);
    set_kb_item(name: "evolution_script/version", value: Ver);


    cpe = build_cpe(value: Ver, exp: "^([0-9.]+)", base:"cpe:/a:evolutionscript:evolutionscript:");

    if(!cpe)
      cpe = 'cpe:/a:evolutionscript:evolutionscript';

    register_product(cpe: cpe, location: install, port: appPort);

    log_message(data:build_detection_report(app: "Evolution Script CMS",
                                            version: Ver,
                                            install: install,
                                            cpe: cpe,
                                            concluded: tmpVer[0]),
                                            port: appPort);
  }
}

exit(0);
