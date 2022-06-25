##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yealink_ip_phone_detect.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Yealink IP Phone Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113281");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-30 13:19:10 +0100 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection");

  script_tag(name:"summary", value:"Detection of Yealink IP Phone");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_yealink_ip_phone_sip_detect.nasl", "gb_yealink_ip_phone_http_detect.nasl");
  script_mandatory_keys("yealink_ipphone/detected");

  exit(0);
}

CPE = "cpe:/h:yealink:ip_phone:";

include( "cpe.inc" );
include( "host_details.inc" );

version = "unknown";
extra = ""; # nb: To make openvas-nasl-lint happy...
model = "";
concluded = "";

foreach proto( make_list( "sip", "http" ) ) {
  if( model == "" || isnull( model ) ) {
    model = get_kb_item( "yealink_ipphone/" + proto + "/model" );
    if( ! isnull( model ) ) {
      CPE = "cpe:/h:yealink:" + model + ":";
    }
  }
  if( version == "unknown" || isnull( version ) ) {
    version = get_kb_item( "yealink_ipphone/" + proto + "/version" );
  }
  port = get_kb_item( "yealink_ipphone/" + proto + "/port" );
  if( ! isnull( port ) ) {
    extra += '\n\n' + toupper( proto ) + "( Port: " + port + " )";
    if( concluded == "" ) {
      concluded = toupper( proto );
    }
    else {
      concluded += ", " + toupper( proto );
    }
    concluded_item = get_kb_item( "yealink_ipphone/" + proto + "/concluded" );
    if( ! isnull( concluded_item ) ) {
      extra += ':\n' + concluded_item;
    }
  }
}

register_and_report_cpe( app: "Yealink IP Phone " + model,
                         ver: version,
                         concluded: concluded,
                         base: CPE,
                         expr: '([0-9.]+)',
                         regPort: 0,
                         extra: extra );

exit(0);
