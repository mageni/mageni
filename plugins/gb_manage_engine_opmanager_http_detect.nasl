###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_opmanager_http_detect.nasl 13787 2019-02-20 12:23:41Z jschulte $
#
# ManageEngine OpManager Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805471");
  script_version("$Revision: 13787 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 13:23:41 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-20 11:52:44 +0530 (Fri, 20 Mar 2015)");
  script_name("ManageEngine OpManager Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of ManageEngine OpManager.

  The script sends a connection request to the server and attempts to detect ManageEngine OpManager
  and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-monitoring/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

http_port = get_http_port(default: 80);

foreach install(make_list_unique("/", cgi_dirs(port: http_port))) {


  if( install == "/" ) {
    url = "/LoginPage.do";
  }
  else {
    url += "/LoginPage.do";
  }
  buf = http_get_cache(item: url, port: http_port);

  if ("ManageEngine" >< buf && ">OpManager<" >< buf) {
    set_kb_item(name: "manageengine/opmanager/detected", value: TRUE);
    set_kb_item(name: "manageengine/opmanager/http/detected", value: TRUE);
    set_kb_item(name: "manageengine/opmanager/http/location", value: install);
    set_kb_item(name: "manageengine/opmanager/http/port", value: http_port);

    concluded = eregmatch(string: buf, pattern: ">OpManager<.*>([ ]?v.[0-9.]+)?",icase: TRUE);
    if(!isnull(concluded[0])) {
      set_kb_item(name: "manageengine/opmanager/http/concluded", value: concluded[0]);
    }

    exit(0);
  }
}

exit(0);
