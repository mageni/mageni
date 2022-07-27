###############################################################################
# OpenVAS Vulnerability Test
#
# PRTG Traffic Grapher Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100215");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PRTG Traffic Grapher Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"PRTG Traffic Grapher, a Windows software for monitoring and
  classifying bandwidth traffic usage is running at this host.");
  script_xref(name:"URL", value:"http://www.paessler.com/prtg6");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "PRTG Traffic Grapher Detection";

port = get_http_port(default:80);

url = string("/login.htm");
buf = http_get_cache(item:url, port:port);
if( buf == NULL )continue;
if( egrep(pattern: 'PRTG Traffic Grapher V[0-9.]+', string: buf, icase: TRUE) &&
    egrep(pattern: 'sensorlist.htm', string: buf, icase: TRUE) )
{
  vers = string("unknown");

  version = eregmatch(string: buf, pattern: 'PRTG Traffic Grapher V([0-9.]+)',icase:TRUE);

  if ( !isnull(version[1]) ) {
    vers=version[1];
  }

  tmp_version = string(vers," under /");
  set_kb_item(name: string("www/", port, "/PRTGTrafficGrapher"), value: tmp_version);
  set_kb_item(name: "prtgtrafficgrapher/detected", value: TRUE);

  cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:paessler:prtg_traffic_grapher:");
  if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  info = string("PRTG Traffic Grapher Version '");
  info += string(vers);
  info += string("' was detected on the remote host\n");
  log_message(port:port,data:info);
}

exit(0);
