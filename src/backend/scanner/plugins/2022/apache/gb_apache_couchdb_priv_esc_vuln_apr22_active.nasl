# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148869");
  script_version("2022-11-08T09:31:32+0000");
  script_tag(name:"last_modification", value:"2022-11-08 09:31:32 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-08 09:27:21 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:10:00 +0000 (Fri, 06 May 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2022-24706");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 3.2.2 Privilege Escalation Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_epmd_detect.nasl");
  script_require_ports("Services/empd", 4369);
  script_mandatory_keys("epmd/detected");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted request to and checks the responses.");

  script_tag(name:"insight", value:"An attacker can access an improperly secured default
  installation without authenticating and gain admin privileges. The CouchDB documentation has
  always made recommendations for properly securing an installation, including recommending using a
  firewall in front of all CouchDB installations.");

  script_tag(name:"affected", value:"Apache CouchDB version 3.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00");
  script_xref(name:"URL", value:"https://medium.com/@_sadshade/couchdb-erlang-and-cookies-rce-on-default-settings-b1e9173a4bcd");

  exit(0);
}

include("byte_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 4369, proto: "epmd");

ports_mapped = get_kb_item("epmd/" + port + "/port_mapping");

if (!ports_mapped || "couchdb" >!< ports_mapped)
  exit(0);

couchdb_port = eregmatch(pattern: "couchdb[0-9a-z.-]+? at port ([0-9]+)", string: ports_mapped);
if (isnull(couchdb_port[1]))
  exit(0);

couchdb_port = couchdb_port[1];

soc = open_sock_tcp(couchdb_port);
if (!soc)
  exit(0);

send(socket: soc, data: raw_string(0x00, 0x15, 0x6e, 0x00, 0x07, 0x00, 0x03, 0x49, 0x9c,
                                   0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x40,
                                   0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41));  # NAME_MSG

recv = recv(socket: soc, length: 5);
if (!recv || "ok" >!< recv) {
  close(soc);
  exit(0);
}

recv = recv(socket: soc, length: 512);
if (!recv || hexstr(substr(recv, 0, 1)) != "001c") {
  close(soc);
  exit(0);
}

challenge = getdword(blob: recv, pos: 9);

md5_reply = MD5(raw_string(0x6d, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x72) + challenge);

challenge_reply = raw_string(0x00, 0x15, "r", 0x01, 0x02, 0x03, 0x04) + md5_reply;

send(socket: soc, data: challenge_reply);
recv = recv(socket: soc, length: 512);
close(soc);

if (recv) {
  report = "It was possible to connect to the Erlang server with the cookie: 'monster'";
  security_message(port: couchdb_port, data: report);
  exit(0);
}

exit(0);
