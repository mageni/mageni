# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107796");
  script_version("2020-04-01T07:08:57+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 17:07:00 +0200 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZOHO ManageEngine AssetExplorer Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_manage_engine_asset_explorer_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_manageengine_assetexplorer_smb_detect.nasl");
  script_mandatory_keys("manageengine/assetexplorer/detected");

  script_tag(name:"summary", value:"The script reports a detected ZOHO ManageEngine AsseetExplorer
  including the version number and build.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/asset-explorer");

  exit(0);
}

CPE = "cpe:/a:zohocorp:manageengine_assetexplorer";

include( "host_details.inc" );

if( ! get_kb_item( "manageengine/assetexplorer/detected" ) )
  exit( 0 );

version = "unknown";
build = "unknown";
extra = "";

foreach proto( make_list( "smb", "http" ) ) {
  version_list = get_kb_list( "manageengine/assetexplorer/" + proto + "/*/version" );

  foreach ver( version_list ) {
    if( ver != "unknown" && version == "unknown" ) {
      version = ver;
      break;
    }
  }

  builds_list = get_kb_list( "manageengine/assetexplorer/" + proto + "/*/build" );
  foreach buildnumber( builds_list ) {
    if( buildnumber != "unknown" && build == "unknown" ) {
      build = buildnumber;
      break;
    }
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

if( ! isnull( concl = get_kb_item( "manageengine/assetexplorer/smb/0/concluded" ) ) ) {
  insloc = get_kb_item( "manageengine/assetexplorer/smb/0/location" );
  extra += '\n- Local Detection over SMB:\n';
  extra += '\n  Location:      ' + insloc;
  extra += '\n  Concluded from:\n' + concl;

  register_product( cpe:CPE, location:insloc, port:0, service:"smb-login" );
}

if( http_ports = get_kb_list( "manageengine/assetexplorer/http/port" ) ) {

  if( extra )
    extra += '\n';

  extra += '\n- Remote Detection over HTTP(s):';

  foreach port( http_ports ) {
    concl  = get_kb_item( "manageengine/assetexplorer/http/" + port + "/concluded" );
    loc    = get_kb_item( "manageengine/assetexplorer/http/" + port + "/location" );
    extra += '\n';
    extra += '\n  Port:           ' + port + "/tcp";
    extra += '\n  Location:       ' + loc;

    if( concl )
      extra += '\n  Concluded from:\n' + concl;

    register_product( cpe:CPE, location:loc, port:port, service:"www" );
  }
}

report = build_detection_report( app:"ZOHO ManageEngine AssetExplorer",
                                 version:version,
                                 patch:build,
                                 install:"/",
                                 cpe:CPE );
if( extra ) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );

exit( 0 );
