###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_detect_http.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# pfSense Detection (HTTP(s))
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806807");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-01-14 18:46:02 +0530 (Thu, 14 Jan 2016)");
  script_name("pfSense Detection (HTTP(s))");

  script_tag(name:"summary", value:"Detection of installed version
  of pfSense.

  This script sends an HTTP GET request, tries to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

pfsPort = get_http_port(default:443);

rcvRes = http_get_cache(item:"/", port:pfsPort);

if('pfsense' >< rcvRes && ('>Login to pfSense<' >< rcvRes ||
   '/themes/pfsense_ng' >< rcvRes || '<title id="pfsense-logo-svg">pfSense Logo</title>' >< rcvRes))
{
  set_kb_item(name:"pfsense/installed", value:TRUE);
  set_kb_item(name:"pfsense/http/installed", value:TRUE);
  set_kb_item(name:"pfsense/http/port", value:pfsPort);

  vers = 'unknown';
}

exit(0);
