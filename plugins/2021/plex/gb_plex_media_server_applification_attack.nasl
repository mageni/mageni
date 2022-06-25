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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145346");
  script_version("2021-02-11T08:04:58+0000");
  script_tag(name:"last_modification", value:"2021-02-11 11:09:43 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-10 07:17:59 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plex Media Server < 1.21.3.4014 SSDP (PMSSDP) Reflection/Amplification DDoS Attack");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(32410, 32412, 32413, 32414);
  script_mandatory_keys("keys/is_public_addr");

  script_tag(name:"summary", value:"Plex Media Server installations in a specific (and uncommon) network
  position could potentially be used to reflect UDP traffic on certain device-discovery ports as part of a
  possible DDoS (distributed denial-of-service) attack.");

  script_tag(name:"insight", value:"Plex Media Server instances which have either been deployed on a
  public-facing network DMZ or in an Internet Data Center (IDC), or with manually configured port-forwarding
  rules which forward specific UDP ports from the public Internet to devices running Plex Media Server, can
  potentially be abused as part of possible DDoS attacks.

  These actions can have the effect of exposing a Plex UPnP-enabled service registration responder to the
  general Internet, where it can be abused to generate reflection/amplification DDoS attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted UDP request and checks the response.");

  script_tag(name:"affected", value:"Plex Media Server prior to version 1.21.3.4014.");

  script_tag(name:"solution", value:"Update to version 1.21.3.4014 or later. For mitigation steps see the
  referenced vendor response.");

  script_xref(name:"URL", value:"https://forums.plex.tv/t/security-regarding-ssdp-reflection-amplification-ddos/687162");
  script_xref(name:"URL", value:"https://www.netscout.com/blog/asert/plex-media-ssdp-pmssdp-reflectionamplification-ddos-attack");
  script_xref(name:"URL", value:"https://mp.weixin.qq.com/s/y8IqT_mT-oC4EVC4y3bVSw");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if (!is_public_addr())
  exit(0);

port_list = make_list(32410, 32412, 32413, 32414);

request = "M-SEARCH * HTTP/1.1";
req_len = strlen(request);

foreach port (port_list) {
  if (!get_udp_port_state(port))
    continue;

  soc = open_sock_udp(port);
  if (!soc)
    continue;

  send(socket: soc, data: request);
  res = recv(socket: soc, length: 4096);
  close(soc);

  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  res_len = strlen(res);

  if (res_len > (10 * req_len)) {
    report = 'We have sent a request of ' + req_len + ' bytes and received a response of ' + res_len + ' bytes.';
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(99);
