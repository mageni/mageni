###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_monlist_enabled.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# NTP Monlist Feature Enabled
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103868");
  script_cve_id("CVE-2013-5211");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11867 $");

  script_name("NTP Monlist Feature Enabled");


  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=1532");
  script_xref(name:"URL", value:"http://lists.ntp.org/pipermail/pool/2011-December/005616.html");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-06 14:14:08 +0100 (Mon, 06 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running");
  script_require_udp_ports(123);

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to cause a denial
of service.");
  script_tag(name:"vuldetect", value:"Send a NTP monlist request and check the response.");
  script_tag(name:"insight", value:"The monlist feature in ntp_request.c in ntpd in NTP before
4.2.7p26 allows remote attackers to cause a denial of service (traffic
amplification) via forged (1) REQ_MON_GETLIST or (2) REQ_MON_GETLIST_1
requests, as exploited in the wild in December 2013.");
  script_tag(name:"solution", value:"Update to NTP 4.2.7p26 or newer or set 'disable monitor' in ntp.conf.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"NTP is prone to a remote denial-of-service vulnerability because it
fails to properly handle certain incoming network packets.");
  script_tag(name:"affected", value:"NTP before 4.2.7p26");

  exit(0);
}


include("byte_func.inc");

port = 123;
if(!get_udp_port_state(port))exit(0);

soc = open_sock_udp(port);
if(!soc)exit(0);

# http://lists.ntp.org/pipermail/pool/2011-December/005616.html
# By default, recent 4.2.7 ntpd defaults to ignoring all mode 7 requests,
# unless "enable mode7" is added to ntp.conf. In 4.2.7p26, the monlist
# support code in ntpd was removed due to amplification risk

req = raw_string(0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00,mkpad(40)); # ntpdc -n -c monlist <ip>

send(socket:soc, data:req);
buf = recv(socket:soc, length:1024);

if(!buf || strlen(buf) < 8)exit(0);

implementation = ord(buf[2]);
request_code   = ord(buf[3]);
rcount         = getword(blob:buf, pos:4);
rsize          = getword(blob:buf, pos:6);

if(rsize == 0 || (implementation != 2 && implementation != 3) || (request_code != 42 || rsize != 72))exit(0);

step = 8;

for (i = 0; i < rcount; i++)
{
  hosts += ord(buf[step+16]) + "." + ord(buf[step+17]) + "." + ord(buf[step+18]) + "." + ord(buf[step+19]) + '\n';
  step += rsize;
}

if(hosts)
  report = 'The Scanner was able to retrieve the following list of recent to this ntpd connected hosts:\n\n' + hosts + '\n';

security_message(port:port, proto:"udp", data:report);

exit(0);
