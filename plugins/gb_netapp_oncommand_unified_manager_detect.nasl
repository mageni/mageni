###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netapp_oncommand_unified_manager_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# NetApp OnCommand Unified Manager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140357");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-05 13:25:35 +0700 (Tue, 05 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp OnCommand Unified Manager Detection");

  script_tag(name:"summary", value:"Detection of NetApp OnCommand Unified Manager.

  The script sends a connection request to the server and attempts to detect NetApp OnCommand Unified Manager.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.netapp.com/us/products/data-infrastructure-management/unified-management.aspx");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

# older versions are installed in "/", newer in "/um"
foreach dir (make_list("/", "/um")) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ("<title>OnCommand Unified Manager</title>" >< res && "OnCommand/OnCommand.nocache.js" >< res) {
    version = "unknown";
    conlUrl = dir;

    set_kb_item(name: "netapp_oncommand_unified_manager/installed", value: TRUE);

    req = http_get_req(port: port, url: dir + '/OnCommand/WW_Help_5.0/GUID-F6B0CAA6-72F1-4846-BE45-EA66AD3DF39A/wwhdata/common/files.js');
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(string: res, pattern: 'OnCommand Unified Manager ([0-9.]+) Online Help', icase: TRUE);
    if(!isnull(vers[1])) {
      version = vers[1];
      conclUrl = dir + '/OnCommand/WW_Help_5.0/GUID-F6B0CAA6-72F1-4846-BE45-EA66AD3DF39A/wwhdata/common/files.js';
    }

    register_and_report_cpe( app: "NetApp Oncommand Unified Manager",
                             ver: version,
                             concluded: vers[0],
                             base: "cpe:/a:netapp:oncommand_unified_manager:",
                             expr: '([0-9.]+)',
                             insloc: dir,
                             regPort: port,
                             conclUrl: conclUrl );

    exit(0);
  }
}

exit(0);
