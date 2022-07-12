###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_jackrabbit_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Apache Jackrabbit Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807896");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 14:29:25 +0530 (Thu, 06 Oct 2016)");
  script_name("Apache Jackrabbit Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Apache Jackrabbit.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

jackPort = get_http_port(default:80);

rcvRes = http_get_cache(port: jackPort, item: "/");

if(">Jackrabbit JCR Server" >< rcvRes && "jackrabbit.apache.org" >< rcvRes)
{
  url = "/repository/default/";

  sndReq = http_get(port:jackPort, item: url);
  rcvRes = http_keepalive_send_recv(port:jackPort, data:sndReq);

  vers = eregmatch(pattern: ">Jackrabbit<.*version ([0-9.]+)<", string: rcvRes);
  if(vers[1]){
    version = vers[1];
  } else {
    version = "unknown";
  }

  set_kb_item(name: "apache/jackrabbit/installed", value: TRUE);
  if (version != "unknown"){
    set_kb_item(name: "apache/jackrabbit/version", value: version);
  }

  cpe = build_cpe(value:version, exp: "^([0-9.]+)", base: "cpe:/a:apache:jackrabbit:");
  if (!cpe){
    cpe = 'cpe:/a:apache:jackrabbit';
  }
  register_product(cpe:cpe, location: "/", port:jackPort);

  log_message(data: build_detection_report(app: "Apache Jackrabbit", version: version, install: "/",
                                           cpe: cpe, concluded: version),
              port: jackPort);
  exit(0);
}
exit(0);