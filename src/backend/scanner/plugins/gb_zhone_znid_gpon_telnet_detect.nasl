###############################################################################
# OpenVAS Vulnerability Test
#
# ZHONE ZNID GPON Device Detection (Telnet)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105404");
  script_version("2020-08-05T09:09:42+0000");
  script_tag(name:"last_modification", value:"2020-08-05 10:06:21 +0000 (Wed, 05 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-10-15 11:45:06 +0200 (Thu, 15 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("ZHONE ZNID GPON Device Detection (Telnet)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/zhone/znid_gpon/detected");

  script_tag(name:"summary", value:"Telnet based detection of ZHONE ZNID GPON devices");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);

if (!banner || "Model: ZNID-GPON" >!< banner)
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "dasanzhone/znid/detected", value: TRUE);
set_kb_item(name: "dasanzhone/znid/telnet/port", value: port);

# Model: ZNID-GPON-2426A1-EU Router
mod = eregmatch(pattern: 'Model: ZNID-GPON-([^- ]+)[^\r\n]+', string: banner);
if (!isnull(mod[1])) {
  model = mod[1];
  concluded = '\n    ' + mod[0];
}

# Release: S3.0.711
vers = eregmatch(pattern: "Release: S([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  concluded += '\n    ' + vers[0];
}

if (concluded)
  set_kb_item(name: "dasanzhone/znid/telnet/" + port + "/concluded", value: concluded);

set_kb_item(name: "dasanzhone/znid/telnet/" + port + "/model", value: model);
set_kb_item(name: "dasanzhone/znid/telnet/" + port + "/version", value: version);

exit(0);
