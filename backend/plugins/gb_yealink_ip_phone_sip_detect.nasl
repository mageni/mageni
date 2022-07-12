##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yealink_ip_phone_sip_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# Yealink IP Phone Detection (SIP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106325");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection (SIP)");

  script_tag(name:"summary", value:"Detection of Yealink IP Phone

  The script attempts to identify Yealink IP Phone via SIP banner to extract the model and version
  number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner(port: port, proto: proto);
concluded = ""; # nb: To make openvas-nasl-lint happy...

if (banner && banner =~ "Yealink SIP") {

  mo = eregmatch(pattern: "SIP-([A-Z0-9_]+)", string: banner);
  if( ! isnull(mo[1])) {
    model = mo[1];
    set_kb_item(name: "yealink_ipphone/sip/model", value: model);
    concluded = mo[0];

    vers = eregmatch(pattern: model + " ([0-9.]+)", string: banner);
    if (!isnull(vers[1])) {
      version =  vers[1];
      concluded += '\n' + vers[0];
      set_kb_item(name: "yealink_ipphone/sip/version", value: version);
    }
  }

  set_kb_item(name: "yealink_ipphone/sip/detected", value: TRUE);
  set_kb_item(name: "yealink_ipphone/sip/proto", value: proto);
  set_kb_item(name: "yealink_ipphone/sip/port", value: port);
  set_kb_item(name:" yealink_ipphone/sip/concluded", value: concluded);
  replace_kb_item(name: "yealink_ipphone/detected", value: TRUE);
}

exit(0);