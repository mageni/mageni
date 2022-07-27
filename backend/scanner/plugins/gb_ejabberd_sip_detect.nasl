# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.144097");
  script_version("2020-06-09T09:51:17+0000");
  script_tag(name:"last_modification", value:"2020-06-10 10:58:50 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 09:05:20 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ejabberd Detection (SIP)");

  script_tag(name:"summary", value:"Detection of ejabberd.

  SIP based detection of ejabberd.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("sip.inc");
include("misc_func.inc");

infos = sip_get_port_proto(default_port: "5060", default_proto: "udp");
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);

if (banner && "ejabberd" >< banner) {
  version = "unknown";

  set_kb_item(name: "ejabberd/detected", value: TRUE);
  set_kb_item(name: "ejabberd/sip/port", value: port);
  set_kb_item(name: "ejabberd/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "ejabberd/sip/" + port + "/concluded", value: banner);

  # ejabberd 20.04-1~bpo10+1
  # ejabberd 20.04
  # ejabberd 18.12.1-2
  vers = eregmatch(pattern: "ejabberd (.*)", string: banner);
  if (!isnull(vers[1]))
    version = chomp(vers[1]);

  set_kb_item(name: "ejabberd/sip/" + port + "/version", value: version);
}

exit(0);
