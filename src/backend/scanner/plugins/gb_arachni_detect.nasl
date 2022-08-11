###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arachni_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Arachni Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.107223");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Arachni Version Detection");
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Arachni.

  The script detects the version of Arachni remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

Port = get_http_port(default: 80);
url = '/d/users/sign_in';

req = http_get(port: Port, item: url);
rcvRes = http_keepalive_send_recv(port: Port, data: req);

if (rcvRes !~ "HTTP/1\.[01] 200" && ">Arachni v" >< rcvRes && "- WebUI v" >< rcvRes) {

  Ver = "unknown";

  tmpVer = eregmatch(pattern: "Arachni v([0-9.]+)  - WebUI v([0-9.]+)",
                    string: rcvRes);
  if (tmpVer[1]) {
    Ver = tmpVer[1];
    set_kb_item(name: "arachni/version", value: Ver);

    if (tmpVer[2]) {
      set_kb_item(name: "arachni/webui", value: tmpVer[2]);
    }
  }

  set_kb_item(name: "arachni/installed", value: TRUE);

  cpe = build_cpe(value: Ver, exp: "^([0-9.]+)", base: "cpe:/a:arachni:arachni:");

  if(!cpe)
    cpe = 'cpe:/a:arachni:arachni';

  register_product(cpe:cpe, location: "/", port: Port);

  log_message(data:build_detection_report(app: "Arachni",
                                          version: Ver,
                                          install: "/",
                                          cpe: cpe,
                                          concluded: tmpVer[0]),
                                          port: Port);
}

exit(0);
