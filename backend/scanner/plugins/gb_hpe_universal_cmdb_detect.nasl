###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_universal_cmdb_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# HPE / Micro Focus Universal CMDB Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808250");
  script_version("$Revision: 10901 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-07-14 16:30:56 +0530 (Thu, 14 Jul 2016)");
  script_name("HPE / Micro Focus Universal CMDB Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of HPE / Micro Focus Universal CMDB.

  This script sends HTTP GET request and try to get the version from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://software.microfocus.com/en-us/products/configuration-management-system-database/overview");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

ucmdbPort = get_http_port(default:8080);

rcvRes = http_get_cache(item:"/ucmdb-ui/login_page.jsp", port:ucmdbPort);

if (rcvRes =~ '<title>(HP(E)? )?Universal CMDB</title>' >< rcvRes &&
   'STATE_LOGIN_FAILS' >< rcvRes && 'User Login:' >< rcvRes) {
  version = "unknown";

  ver = eregmatch(pattern:'class="version">(HP(E)? )?Universal CMDB ([0-9.]+)', string:rcvRes);
  if (!isnull(ver[3]))
    version = ver[3];

  set_kb_item(name:"HP/UCMDB/Installed", value:TRUE);

  ## TODO: maybe change cpe to micro focus
  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/a:hp:universal_cmbd_foundation:");
  if(!cpe)
    cpe = "cpe:/a:hp:universal_cmbd_foundation";

  register_product(cpe:cpe, location:"/", port:ucmdbPort);

  log_message(data:build_detection_report(app: "HP / Micro Focus Universal CMDB", version: version, install: "/",
                                          cpe: cpe, concluded: ver[0]),
              port: ucmdbPort);
  exit(0);
}

exit(0);
