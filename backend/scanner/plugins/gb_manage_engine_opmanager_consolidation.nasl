# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113337");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-15 10:07:44 +0100 (Fri, 15 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine OpManager Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_manage_engine_opmanager_http_detect.nasl",
  "gb_manage_engine_opmanager_smb_detect.nasl");
  script_mandatory_keys("manageengine/opmanager/detected");

  script_tag(name:"summary", value:"Consolidates the result of ManageEngine OpManager
  detections via SMB and HTTP.");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-monitoring/");

  exit(0);
}

CPE = "cpe:/a:zohocorp:manageengine_opmanager:";

include( "host_details.inc" );
include( "cpe.inc" );

if( ! version = get_kb_item( "manageengine/opmanager/smb/version" ) ) version = "unknown";
port = get_kb_item( "manageengine/opmanager/http/port" );
url = get_kb_item( "manageengine/opmanager/http/location" );
installDir = get_kb_item( "manageengine/opmanager/smb/location" );

extra = "Concluded from:";
concluded = "";

if( http_concluded = get_kb_item( "manageengine/opmanager/http/concluded" ) ) {
  extra += '\n\nHTTP:\n' + http_concluded;
  concluded += "HTTP";
}

if( smb_concluded = get_kb_item( "manageengine/opmanager/smb/concluded" ) ) {
  extra += '\n\nSMB:\n' + smb_concluded;
  if( concluded == "" )
    concluded = "SMB";
  else
    concluded += ", SMB";
}

register_and_report_cpe( app: "ManageEngine OpManager",
                         ver: version,
                         concluded: concluded,
                         base: CPE,
                         expr: '([0-9.]+)',
                         insloc: installDir,
                         regPort: port,
                         conclUrl: url,
                         extra: extra );

exit( 0 );
