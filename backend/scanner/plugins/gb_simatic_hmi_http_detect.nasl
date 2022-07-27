###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_hmi_http_detect.nasl 12659 2018-12-05 09:26:36Z cfischer $
#
# Siemens SIMATIC HMI Device Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141683");
  script_version("$Revision: 12659 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 10:26:36 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 14:38:36 +0700 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC HMI Device Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Siemens SIMATIC HMI devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: '/start.html');

if ('Device Status of HMI_Panel' >< res && 'Welcome on HMI_Panel' >< res) {
  set_kb_item(name: "simatic_hmi/detected", value: TRUE);
  set_kb_item(name: "simatic_hmi/http/detected", value: TRUE);
  set_kb_item(name: "simatic_hmi/http/port", value: port);

  # <b>Device Type</b></td><td class=\"sph_td\">TP700 Comfort&nbsp;</td>
  mod = eregmatch(pattern: 'Device Type</b></td><td class="sph_td">([^&;]+)', string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "simatic_hmi/http/" + port + "/model", value: chomp(mod[1]));

  # Image version</b></td><td class="sph_td">V14.00.01.00_11.01&nbsp;
  vers = eregmatch(pattern: 'Image version<.*>V([0-9._]+)', string: res);
  if (!isnull(vers[1])) {
    version = str_replace( string: vers[1], find: "_", replace: ".");
    set_kb_item(name: "simatic_hmi/http/" + port + "/fw_version", value: version);
  }
}

exit(0);