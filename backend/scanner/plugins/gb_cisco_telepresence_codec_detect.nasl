###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_codec_detect.nasl 11450 2018-09-18 10:48:31Z tpassfeld $
#
# Cisco TelePresence Codec Remote Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.114033");
  script_version("$Revision: 11450 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:48:31 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-17 12:00:40 +0200 (Mon, 17 Sep 2018)");
  script_name("Cisco TelePresence Codec Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Cisco TelePresence Codec.

  This script sends HTTP GET request and try to ensure the presence of
  Cisco TelePresence Codec.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/web/signin";
res = http_get_cache(port: port, item: url);
if("The resource could not be found.<br />" >< res) {
  url = "/web/sessions/new";
  res = http_get_cache(port: port, item: url);
}

if(res =~ '<link href="/static/vega.[0-9a-zA-Z]+.min.css" media="screen" rel="stylesheet" type="text/css" />'
   && res =~ '<script src="/static/vega.[0-9a-zA-Z]+.min.js" type="text/javascript"></script>') {

  #version/model detection requires login
  version = "unknown";

  set_kb_item(name: "cisco/telepresence/codec/detected", value: TRUE);
  set_kb_item(name: "cisco/telepresence/codec/" + port + "/detected", value: TRUE);

  cpe = "cpe:/a:cisco:telepresence_codec:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Cisco TelePresence Codec",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Login required for version/model detection.");
}

exit(0);
