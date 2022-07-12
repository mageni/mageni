###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeswitch_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# FreeSWITCH Version Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804024");
  script_version("$Revision: 13734 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-10-07 18:21:20 +0530 (Mon, 07 Oct 2013)");
  script_name("FreeSWITCH Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of FreeSWITCH.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");
  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("sip.inc");
include("cpe.inc");
include("host_details.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner(port: port, proto: proto);
if (! banner || "FreeSWITCH" >!< banner) exit(0);

version = "unknown";

switchVer = eregmatch(pattern: "FreeSWITCH-.*/([0-9.]+)", string: banner);

if(switchVer) {
  set_kb_item(name: "FreeSWITCH/Version", value: switchVer[1]);
  version = switchVer[1];
}

set_kb_item(name: "FreeSWITCH/installed",value: TRUE);

cpe = build_cpe(value: switchVer[1], exp: "^([0-9.]+)", base: "cpe:/a:freeswitch:freeswitch:");
if(isnull(cpe))
  cpe = 'cpe:/a:freeswitch:freeswitch';

location = port + "/" + proto;

register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

log_message(data: build_detection_report(app:"FreeSWITCH", version: version,
                                         install: location, cpe: cpe,
                                         concluded: switchVer[0]), port: port, proto: proto);

exit(0);