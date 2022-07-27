###############################################################################
# OpenVAS Vulnerability Test
#
# FreeSWITCH Version Detection (SIP)
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
  script_version("2019-12-06T09:54:56+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-06 09:54:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-10-07 18:21:20 +0530 (Mon, 07 Oct 2013)");

  script_name("FreeSWITCH Detection (SIP)");

  script_tag(name:"summary", value:"Detection of FreeSWITCH over SIP.

  This script performs SIP based detection of FreeSWITCH.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("sip.inc");
include("host_details.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner(port: port, proto: proto);
if (!banner || "FreeSWITCH" >!< banner)
  exit(0);

set_kb_item(name: "freeswitch/detected", value: TRUE);
set_kb_item(name: "freeswitch/sip/" + proto + "/detected", value: TRUE);
set_kb_item(name: "freeswitch/sip/" + proto + "/port", value: port);
set_kb_item(name: "freeswitch/sip/" + proto + "/" + port + "/concluded", value: banner);

version = "unknown";

switchVer = eregmatch(pattern: "FreeSWITCH-.*/([0-9.]+)", string: banner);

if (!isnull(switchVer[1]))
  version = switchVer[1];

set_kb_item(name: "freeswitch/sip/" + proto + "/" + port + "/version", value: version);

exit(0);
