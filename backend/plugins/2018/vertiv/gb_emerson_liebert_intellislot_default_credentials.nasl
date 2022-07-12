###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emerson_liebert_intellislot_default_credentials.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# Emerson Liebert IntelliSlot Devices Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113235");
  script_version("$Revision: 12045 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-24 13:03:33 +0200 (Tue, 24 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-12922");

  script_name("Emerson Liebert IntelliSlot Devices Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_emerson_liebert_intellislot_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("liebert/intellislot/detected");

  script_tag(name:"summary", value:"Emerson Liebert IntelliSlot devices use default credentials.");
  script_tag(name:"vuldetect", value:"Tries to login using the default credentials.");
  script_tag(name:"insight", value:"The default administrator account is called 'Liebert',
  using the password 'Liebert'.");
  script_tag(name:"impact", value:"Successful exploitation would give an attecker full
  administrative access over the target device.");
  script_tag(name:"affected", value:"All Emerson Liebert IntelliSlot devices.");
  script_tag(name:"solution", value:"Change the password of the 'Liebert' account.");

  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97372");

  exit(0);
}

CPE = "cpe:/h:liebert:intellislot";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

username = "Liebert";
password = "Liebert";

auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/config/configUser.htm", add_headers: auth_header );
buf = http_keepalive_send_recv( data: req, port: port );

if( buf =~ 'HTTP/[0-9.]+ 200 OK' && 'enableObject("passwordAdmin");' ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
