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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107665");
  script_version("2019-06-24T12:35:18+0000");
  script_tag(name:"last_modification", value:"2019-06-24 12:35:18 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-05-25 16:57:20 +0200 (Sat, 25 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine ServiceDesk Plus Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_manageengine_servicedesk_plus_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_manage_engine_servicedesk_plus_smb_detect.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_tag(name:"summary", value:"The script reports a detected ManageEngine ServiceDesk Plus including the
  version number.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk");

  exit(0);
}

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

include("host_details.inc");

if( ! get_kb_item( "manageengine/servicedesk_plus/detected" ) )
  exit( 0 );

version = "unknown";
build = "unknown";

foreach proto( make_list( "smb", "http" ) ) {
  version_list = get_kb_list( "manageengine/servicedesk_plus/" + proto + "/*/version" );

  foreach ver( version_list ) {
    if( ver != "unknown" && version == "unknown" )
      version = ver;
  }

  builds_list = get_kb_list( "manageengine/servicedesk_plus/" + proto + "/*/build" );
  foreach buildnumber( builds_list ) {
    if( buildnumber != "unknown" && build == "unknown" )
      build = buildnumber;
  }

  if( version != "unknown" && build != "unknown" ) {
    CPE += ":" + version + ":b" + build;
    break;
  }
  else if( version != "unknown" ) {
    CPE += ":" + version;
    break;
  }
}

if( ! isnull( concl = get_kb_item( "manageengine/servicedesk_plus/smb/0/concluded" ) ) ) {
  insloc = get_kb_item( "manageengine/servicedesk_plus/smb/0/location" );
  extra += '\nLocal Detection over SMB:\n';
  extra += '  Concluded from:' + concl + '\n';
  extra += '  Location:      ' + insloc + '\n';

  register_product( cpe:CPE, location:insloc, port:0, service:"smb-login");
}

if( http_ports = get_kb_list( "manageengine/servicedesk_plus/http/port" ) ) {
  extra += '\nRemote Detection over HTTP(s):\n';

  foreach port( http_ports ) {
    concl = get_kb_item( "manageengine/servicedesk_plus/http/" + port + "/concluded" );
    loc = get_kb_item( "manageengine/servicedesk_plus/http/" + port + "/location" );
    extra += '  Port:           ' + port + '/tcp\n';
    extra += '  Location:       ' + loc + '\n';
    extra += '  Concluded from: ' + concl + '\n';

    register_product( cpe:CPE, location:loc, port:port, service:"www" );
  }
}

report = build_detection_report( app:"ManageEngine ServiceDesk Plus",
                                 version:version,
                                 patch:build,
                                 install:"/",
                                 cpe:CPE );
if( extra )
  report += '\n\nDetection methods:\n';
  report += extra;

log_message( port:0, data:report );

exit( 0 );
