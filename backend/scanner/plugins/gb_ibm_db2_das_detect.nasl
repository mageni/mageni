###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Detection (DAS)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801502");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-03-18T09:45:18+0000");
  script_tag(name:"last_modification", value:"2020-03-18 09:45:18 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Db2 Detection (DAS)");

  script_tag(name:"summary", value:"Db2 Administration Server (DAS) based detection of IBM Db2.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_udp_ports(523);

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

port = 523;

if (!get_udp_port_state(port))
  exit(0);

soc = open_sock_udp(port);
if (!soc)
  exit(0);

base = 11;
## SQL query to get version
raw_data = string('DB2GETADDR\x00SQL08020\x00');

send(socket:soc, data:raw_data);
result = recv(socket:soc, length:1000);
close(soc);

if (!result || result !~ "^DB2RETADDR" || strlen(result) < 14)
  exit(0);

if (ord(result[0]) == 68 && ord(result[1] == 66) && ord(result[2]) == 50 &&
    ord(result[11]) == 83 && ord(result[12]) == 81 && ord(result[13]== 76)) {
  data = "";
  for (i = 0; i < 50; i++)
    data = data + result[base+i];

  set_kb_item(name:"ibm/db2/detected", value:TRUE);
  set_kb_item(name:"ibm/db2/das/detected", value:TRUE);
  set_kb_item(name:"ibm/db2/das/port", value:port);
  set_kb_item(name:"OpenDatabase/found", value:TRUE);

  version = "unknown";

  # DB2RETADDR.SQL09050.SYNCOMPACT-2U
  vers = eregmatch(pattern:"([0-9]+)", string:data);
  if (!isnull(vers[1])) {
    part = eregmatch(pattern:"([0-9]{2})([0-9]{2})([0-9])", string:vers[1]);
    if (max_index(part) == 4) {
      for (i = 1; i <= 2; i++) {
        if (part[i] =~ "^0")
          part[i] = ereg_replace(pattern:"^0([0-9])", string:part[i], replace:"\1");
      }

      if (part[1] =~ "^[0-8]$")
        version = part[1] + "." + part[2] + "." + part[3];
      else
        version = part[1] + "." + part[2] + ".0." + part[3];
    }

    set_kb_item(name:"ibm/db2/das/" + port + "/concluded", value:bin2string(ddata:result, noprint_replacement:""));
  }

  register_service(port: port, proto: "db2-das", ipproto: "udp");

  set_kb_item(name:"ibm/db2/das/" + port + "/version", value:version);
}

exit(0);
