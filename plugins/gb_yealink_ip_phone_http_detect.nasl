##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yealink_ip_phone_http_detect.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Yealink IP Phone Detection (HTTP)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.113280");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-25 14:49:10 +0200 (Thu, 25 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Yealink IP Phone

  The script attempts to identify Yealink IP Phone via HTTP banner to extract the model and version
  number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_mandatory_keys("sip/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default: 80 );

url = "/servlet?m=mod_listener&p=login&q=loginForm";

buf = http_get_cache( port: port, item: url );
if( buf =~ 'try again [0-9]+ minutes later' && buf =~ 'You are not authorized' ) {
  url = "/servlet?p=login&q=loginForm&jumpto=status";
  buf = http_get_cache( port: port, item: url );
}

concluded = ""; # nb: To make openvas-nasl-lint happy...

if( buf =~ 'Server: yealink' || buf =~ '<title>Yealink' ) {

  mo = eregmatch( pattern: 'g_phonetype[ ]*=[ ]*["\']([A-Z0-9_-]+)["\']', string: buf );
  if( ! isnull( mo[1] ) ) {
    set_kb_item( name: "yealink_ipphone/http/model", value: mo[1] );
  }
  else {
    mo = eregmatch( pattern: '<script>T\\("[^")]+ ([A-Z0-9_-]+)"\\)', string: buf );
    if( ! isnull( mo[1] ) ) {
      set_kb_item( name: "yealink_ipphone/http/model", value: mo[1] );
    }
  }

  if( ! isnull( mo[1] ) ) {
    concluded = mo[0];
  }

  vers = eregmatch( pattern: 'g_str[Ff]irmware[ ]*=[ ]*["\']([0-9.]+)["\']', string: buf );
  if ( ! isnull( vers[1] ) ) {
    set_kb_item( name: "yealink_ipphone/http/version", value: vers[1] );
  }
  else {
    vers = eregmatch( pattern: 'language[/][^.]+[.]js[?]([0-9.]+)', string: buf );
    if( ! isnull( vers[1] ) ) {
      set_kb_item( name: "yealink_ipphone/http/version", value: vers[1] );
    }
  }

  if( ! isnull( vers[1] ) ) {
    concluded += '\n' + vers[0];
  }

  set_kb_item( name: "yealink_ipphone/http/detected", value: TRUE );
  set_kb_item( name: "yealink_ipphone/http/port", value: port );
  set_kb_item( name: "yealink_ipphone/http/concluded", value: concluded );
  replace_kb_item( name: "yealink_ipphone/detected", value: TRUE );
}

exit(0);
