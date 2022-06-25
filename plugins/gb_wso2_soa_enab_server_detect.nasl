###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wso2_soa_enab_server_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# WSO2 SOA Enablement Server Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808060");
  script_version("$Revision: 10899 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-05-25 15:44:11 +0530 (Wed, 25 May 2016)");
  script_name("WSO2 SOA Enablement Server Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of WSO2 SOA Enablement Server.

  This script check the presence of WSO2 SOA Enablement Server from the
  banner and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WSO2_SOA/banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


wsoPort = get_http_port(default:8080);

banner = get_http_banner(port:wsoPort);

if(banner && "Server: WSO2 SOA Enablement Server" >< banner)
{
  wsoVer = "unknown";
  install = "/";

  vers = eregmatch(pattern: "Server: WSO2 SOA Enablement Server.*build SSJ-([^)]+))", string: banner);
  if (!isnull(vers[1])) {
    wsoVer = vers[1];
    set_kb_item(name: "WSO2/SOA/Enablement_Server/version", value: wsoVer);
  }

  set_kb_item(name:"WSO2/SOA/Enablement_Server/Installed", value:TRUE);

  cpe = build_cpe(value: wsoVer, exp: "^([0-9.-]+)", base: "cpe:/a:wso2:enablement_server_for_java:");
  if (!cpe)
    cpe = "cpe:/a:wso2:enablement_server_for_java";

  register_product(cpe:cpe, location:install, port:wsoPort);

  log_message(data: build_detection_report(app: "WSO2 SOA Enablement Server",
                                           version: wsoVer,
                                           install: install,
                                           cpe: cpe,
                                           concluded: vers[0]),
              port: wsoPort);
  exit(0);
}

exit(0);
