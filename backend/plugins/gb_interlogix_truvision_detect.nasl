###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interlogix_truvision_detect.nasl 12900 2018-12-28 16:37:41Z tpassfeld $
#
# Interlogix TruVision Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.114056");
  script_version("$Revision: 12900 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 17:37:41 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-28 16:12:41 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Interlogix TruVision Detection");

  script_tag(name:"summary", value:"Detection of Interlogix TruVision.

  The script sends a connection request to the server and attempts to detect the web interface for TruVision.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.interlogix.com/video/product/truvision-nvr-22");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/Login.htm";
res = http_get_cache(port: port, item: url);

if("var gHashCookie = new Hash.Cookie('NetSuveillanceWebCookie',{duration:" >< res
   && "window.addEvent('domready',function(){" >< res && "var iLanguage=" >< res) {
  version = "unknown";
  install = "/";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  cpe = "cpe:/a:interlogix:truvision:";

  set_kb_item(name: "interlogix/truvision/detected", value: TRUE);
  set_kb_item(name: "interlogix/truvision/" + port + "/detected", value: TRUE);

  #If you need the version, make sure to run "2018/interlogix/gb_interlogix_truvision_default_credentials.nasl" first.

  register_and_report_cpe(app: "Interlogix TruVision",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);
