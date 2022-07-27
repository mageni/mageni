###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_opmanager_detect.nasl 8820 2018-02-15 05:56:30Z ckuersteiner $
#
# Zoho ManageEngine OpManager Detection
#
# Authors:
# Rinu Kuriakose <secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312701");
 script_version("$Revision: 8820 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2018-02-15 06:56:30 +0100 (Thu, 15 Feb 2018) $");
 script_tag(name:"creation_date", value:"2015-03-20 11:52:44 +0530 (Fri, 20 Mar 2015)");
 script_name("Zoho ManageEngine OpManager Detection");

 script_tag(name: "summary" , value: "Detection of ManageEngine OpManager.

The script sends a connection request to the server and attempts to detect ManageEngine OpManager and to extract
its version.");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 443);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

http_port = get_http_port(default: 80);

url = "/LoginPage.do";
buf = http_get_cache(item: url, port: http_port);

if ("ManageEngine" >< buf && ">OpManager<" >< buf) {
  vers = "unknown";
  install = "/";

  # <h2>OpManager<span>v 12.0</span></h2>
  # This is not that reliable since no build information available
  version = eregmatch(string: buf, pattern: ">OpManager<.*>( )?v.([0-9.]+)",icase: TRUE);
  if (!isnull(version[2]))
      vers = version[2];

  set_kb_item(name: "OpManager/installed",value: TRUE);

  cpe = build_cpe(value: vers, exp: "^([0-9 a-z.]+)", base: "cpe:/a:zohocorp:manageengine_opmanager:");
  if (!cpe)
    cpe = 'cpe:/a:zohocorp:manageengine_opmanager';

  register_product(cpe: cpe, location: install, port: http_port);

  log_message(data: build_detection_report(app: "ManageEngine OpManager", version: vers, install: install,
                                           cpe: cpe, concluded: version[0]),
              port: http_port);
  exit(0);
}

exit(0);
