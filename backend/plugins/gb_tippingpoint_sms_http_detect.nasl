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
  script_oid("1.3.6.1.4.1.25623.1.0.108567");
  script_version("2019-04-25T09:49:09+0000");
  script_tag(name:"last_modification", value:"2019-04-25 09:49:09 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TrendMicro TippingPoint Security Management System (SMS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of a TrendMicro TippingPoint Security Management System (SMS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

buf = http_get_cache( item:"/", port:port );

# nb: There are no much other detection points left on the initial page.
if( "<title>TippingPoint Security Management System</title>" >< buf ) {

  version = "unknown";

  # nb: Other possible API endpoints:
  # /dashboard/api/v1/banner_info
  # /dashboard/api/v1/capability (requires Auth)
  url = "/dashboard/api/v1/common_info";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # {"data":{"system_timezone":"Asia/Hong_Kong","version_number":"5.1.1.109821","is_unlicensed_sms":false,"timezone_offset":8,"patch_number":null},"info":{"message":"Success","status":"SUCCESS"}}
  # {"data":{"system_timezone":"CET","version_number":"5.0.0.106258","is_unlicensed_sms":false,"timezone_offset":2,"patch_number":"5.0.0.106258.1"},"info":{"message":"Success","status":0}}
  # {"data":{"system_timezone":"America/New_York","version_number":"5.0.1.108768","is_unlicensed_sms":false,"timezone_offset":-4,"patch_number":"5.0.1.108768.1"},"info":{"message":"Success","status":0}}
  # {"data":{"system_timezone":"America/Sao_Paulo","version_number":"4.6.0.101914.1","is_unlicensed_sms":false,"timezone_offset":-3},"info":{"message":"Success","status":0}}
  vers_num = eregmatch( pattern:'"version_number":"([^"]+)"', string:buf );
  if( vers_num[1] ) {
    version = vers_num[1];
    set_kb_item( name:"tippingpoint/sms/http/" + port + "/concluded", value:vers_num[0] );
    set_kb_item( name:"tippingpoint/sms/http/" + port + "/concludedUrl", value:report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }

  set_kb_item( name:"tippingpoint/sms/http/" + port + "/version", value:version );
  set_kb_item( name:"tippingpoint/sms/detected", value:TRUE );
  set_kb_item( name:"tippingpoint/sms/http/detected", value:TRUE );
  set_kb_item( name:"tippingpoint/sms/http/port", value:port );
}

exit( 0 );