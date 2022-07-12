###############################################################################
# OpenVAS Vulnerability Test
#
# ejabberd Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100486");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-06-09T09:51:17+0000");
  script_tag(name:"last_modification", value:"2020-06-10 10:58:50 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("ejabberd Detection (XMPP)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("xmpp_detect.nasl");
  script_require_ports("Services/xmpp", 5269);

  script_tag(name:"summary", value:"XMPP based detection of ejabberd.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if (!port = get_port_for_service(default: 5269, proto: "xmpp-server"))
  exit(0);

server = get_kb_item("xmpp/" + port + "/server");

if ("ejabberd" >< server) {
  version = "unknown";

  set_kb_item(name: "ejabberd/detected", value: TRUE);
  set_kb_item(name: "ejabberd/xmpp/port", value: port);

  vers = get_kb_item(string("xmpp/", port, "/version"));
  if (!isnull(vers)) {
    version = vers;
    set_kb_item(name: "ejabberd/xmpp/" + port + "/concluded", value: vers);
  }

  set_kb_item(name: "ejabberd/xmpp/" + port + "/version", value: version);
}

exit(0);
