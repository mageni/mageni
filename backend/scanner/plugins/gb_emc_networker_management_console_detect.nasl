###############################################################################
# OpenVAS Vulnerability Test
#
# EMC Networker Management Console Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103124");
  script_version("2019-12-12T19:26:57+0000");
  script_tag(name:"last_modification", value:"2019-12-12 19:26:57 +0000 (Thu, 12 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("EMC Networker Management Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The EMC Networker Management Console is running at this port.");

  script_xref(name:"URL", value:"http://www.emc.com/products/detail/software/networker.htm");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:9000);

url = "/";
buf = http_get_cache(item:url, port:port);
if(!buf)
  exit(0);

if(egrep(pattern:"<title>Welcome to NetWorker Management Console", string:buf, icase:TRUE)) {

  version = "unknown";
  install = url;
  cpe = "cpe:/a:emc:networker";
  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"EMC Networker Management Console",
                                          version:version,
                                          install:install,
                                          cpe:cpe),
              port:port);
}

exit(0);
