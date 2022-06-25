###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_web_detect.nasl 12564 2018-11-28 15:36:41Z cfischer $
#
# Western Digital MyCloud Products Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108034");
  script_version("$Revision: 12564 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 16:36:41 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-01-04 10:00:00 +0100 (Wed, 04 Jan 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Western Digital MyCloud Products Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of
  Western Digital MyCloud products.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
res = http_get_cache( item:"/", port:port );

# Possible response:
#var _PROJECT_MODEL_ID_LIGHTNING = "WDMyCloudEX4";
#var _PROJECT_MODEL_ID_KINGS_CANYON = "WDMyCloudEX2";
#var _PROJECT_MODEL_ID_ZION = "WDMyCloudMirror";
#var _PROJECT_MODEL_ID_GLACIER = "WDMyCloud";
#var _PROJECT_MODEL_ID_YELLOWSTONE = "WDMyCloudEX4100";
#var _PROJECT_MODEL_ID_YOSEMITE = "WDMyCloudEX2100";
#var _PROJECT_MODEL_ID_SPRITE = "WDMyCloudDL4100";
#var _PROJECT_MODEL_ID_AURORA = "WDMyCloudDL2100";
#var _PROJECT_MODEL_ID_BLACKICE = "WDMyCloudEX1100";
#var MODEL_ID = "WDMyCloudMirror";
#var MODEL_ID = "MyCloudEX2Ultra";
#
# The latest "MODEL_ID" is what's currently running on the device.

if( res =~ "^HTTP/1\.[01] 200" && ( res =~ 'MODEL_ID = "(WD)?MyCloud.+"' || "/web/images/logo_WDMyCloud.png" >< res ) ) {

  version = "unknown";
  model   = "unknown";

  # nb: This only offers the major version and seems to be available via 443 only
  # <info><ip></ip><device>WDMyCloudEX4100</device><hw_ver>WDMyCloudEX4100</hw_ver><version>2.30</version><url></url></info>
  # <info><ip></ip><device>MyCloudEX2Ultra</device><hw_ver>MyCloudEX2Ultra</hw_ver><version>2.30</version><url></url></info>
  # <info><ip></ip><device>$devicename</device><hw_ver>MyCloudEX2Ultra</hw_ver><version>2.31</version><url></url></info>
  # <info><ip></ip><device>$devicename</device><hw_ver>WDMyCloudMirror</hw_ver><version>2.11</version><url></url></info>
  url  = "/xml/info.xml";
  req  = http_get( item:url, port:port );
  res2 = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );

  mo = eregmatch( pattern:'var MODEL_ID = "(WD)?MyCloud([a-zA-Z0-9]+)";', string:res );
  if( mo[2] ) {
    model     = mo[2];
    concluded = mo[0];
    conclUrl  = report_vuln_url( port:port, url:"/", url_only:TRUE );
  } else {
    mo = eregmatch( pattern:"<hw_ver>(WD)?MyCloud([a-zA-Z0-9]+)</hw_ver>", string:res2 );
    if( mo[2] ) {
      model     = mo[2];
      concluded = mo[0];
      conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  vers = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res2 );
  if( vers[1] ) {
    version = vers[1];
    if( concluded )
      concluded += '\n';
    concluded += vers[0];
    if( conclUrl && url >!< conclUrl )
      conclUrl += ', ' + report_vuln_url( port:port, url:url, url_only:TRUE );
    else if( ! conclUrl )
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  set_kb_item( name:"wd-mycloud/detected", value:TRUE );
  set_kb_item( name:"wd-mycloud/http/detected", value:TRUE );
  set_kb_item( name:"wd-mycloud/http/port", value:port );
  set_kb_item( name:"wd-mycloud/http/" + port + "/version", value:version );
  set_kb_item( name:"wd-mycloud/http/" + port + "/model", value:model );

  if( concluded )
    set_kb_item( name:"wd-mycloud/http/" + port + "/concluded", value:concluded );

  if( conclUrl )
    set_kb_item( name:"wd-mycloud/http/" + port + "/concludedUrl", value:conclUrl );

}

exit( 0 );