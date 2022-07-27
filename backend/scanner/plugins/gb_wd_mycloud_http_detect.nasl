###############################################################################
# OpenVAS Vulnerability Test
#
# Western Digital My Cloud Products Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_version("2021-01-05T20:30:19+0000");
  script_tag(name:"last_modification", value:"2021-01-07 11:57:53 +0000 (Thu, 07 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-01-04 10:00:00 +0100 (Wed, 04 Jan 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Western Digital My Cloud / WD Cloud Products Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Western Digital My Cloud products (Called 'WD Cloud' in Japan).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

url = "/";
port = http_get_port( default:80 );
res = http_get_cache( item:url, port:port );
if( ! res )
  exit( 0 );

# nb: My Cloud OS 5 blocks our user agent (both, the User-Agent and the X-Scanner one. Probably
# blocked by mod_security) so try with a standard user agent and don't add the X-Scanner header...
if( res =~ "^HTTP/1\.[01] 403" ) {
  ua = "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0";
  req = http_get_req( port:port, url:url, user_agent:ua, dont_add_xscanner:TRUE );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
}

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
#and:
#var MODEL_ID = "WDMyCloudMirror";
#or:
#var MODEL_ID = "MyCloudEX2Ultra";
#
# There is also a variant of these devices available in Japan which reports itself as:
#var MODEL_ID = "WDCloud";
# nb: The other _PROJECT_MODEL parts are the same as the global version.
#
# The last "MODEL_ID" is what's currently running on the device.

if( res =~ "^HTTP/1\.[01] 200" && ( res =~ 'MODEL_ID = "((WD)?MyCloud[^"]*|WDCloud)"' || "/web/images/logo_WDMyCloud.png" >< res ) ) {

  version = "unknown";
  model   = "unknown";

  # nb: This only offers the major version and seems to be available via 443 only
  # <info><ip></ip><device>WDMyCloudEX4100</device><hw_ver>WDMyCloudEX4100</hw_ver><version>2.30</version><url></url></info>
  # <info><ip></ip><device>MyCloudEX2Ultra</device><hw_ver>MyCloudEX2Ultra</hw_ver><version>2.30</version><url></url></info>
  # <info><ip></ip><device>$devicename</device><hw_ver>MyCloudEX2Ultra</hw_ver><version>2.31</version><url></url></info>
  # <info><ip></ip><device>$devicename</device><hw_ver>WDMyCloudMirror</hw_ver><version>2.11</version><url></url></info>
  # nb: This is the variant for the Japanese market:
  # <info><ip></ip><device>WDCloud</device><hw_ver>WDCloud</hw_ver><version>2.00</version><url></url></info>
  url  = "/xml/info.xml";
  req  = http_get( item:url, port:port );
  res2 = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );

  mo = eregmatch( pattern:'var MODEL_ID = "((WD)?MyCloud([^"]*)|WDCloud)";', string:res );
  if( mo ) {
    if( mo[1] && mo[1] == "WDCloud" ) # var MODEL_ID = "WDCloud";
      model = "WD Cloud";
    else if( mo[3] ) # var MODEL_ID = "WDMyCloudMirror";
      model = mo[3];
    else # var MODEL_ID = "WDMyCloud";
      model = "base";
    concluded = mo[0];
    conclUrl  = http_report_vuln_url( port:port, url:"/", url_only:TRUE );
  }

  if( model == "unknown" ) {
    mo = eregmatch( pattern:"<hw_ver>((WD)?MyCloud([^<]*)|WDCloud)</hw_ver>", string:res2 );
    if( mo ) {
      if( mo[1] && mo[1] == "WDCloud" ) # var MODEL_ID = "WDCloud";
        model = "WD Cloud";
      else if( mo[3] ) # var MODEL_ID = "WDMyCloudMirror";
        model = mo[3];
      else # var MODEL_ID = "WDMyCloud";
        model = "base";
      concluded = mo[0];
      conclUrl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  vers = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res2 );
  if( vers[1] ) {
    version = vers[1];
    if( concluded )
      concluded += '\n';
    concluded += vers[0];
    if( conclUrl && url >!< conclUrl )
      conclUrl += ', ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    else if( ! conclUrl )
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  url = "/nas/v1/locale";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( res && res =~ "^HTTP/1\.[01] 200" && res =~ "Content-Type\s*:\s*application/json" ) {
    admin_user = eregmatch( string:res, pattern:'\\{[^}]*"admin_username":"([^"]+)"[^}]*\\}', icase:FALSE );
    if( admin_user[1] ) {
      set_kb_item( name:"wd-mycloud/http/" + port + "/admin_user", value:admin_user[1] );
      set_kb_item( name:"wd-mycloud/http/" + port + "/extra", value:admin_user[0] );
      set_kb_item( name:"wd-mycloud/http/" + port + "/extraUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
    }
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
