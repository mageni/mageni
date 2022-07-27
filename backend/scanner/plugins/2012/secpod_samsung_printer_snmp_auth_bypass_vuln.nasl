###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_samsung_printer_snmp_auth_bypass_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Samsung Printer SNMP Hardcoded Community String Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902935");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2012-4964");
  script_bugtraq_id(56692);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-28 13:37:22 +0530 (Wed, 28 Nov 2012)");
  script_name("Samsung Printer SNMP Hardcoded Community String Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("SNMP");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161, 1118);
  script_mandatory_keys("SNMP/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/281284");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/196");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118413/samsung-backdoor.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access an affected device
  with administrative privileges, make changes to the device configuration and
  access to sensitive information.");

  script_tag(name:"insight", value:"Samsung printers (as well as some Dell printers manufactured by Samsung)
  contain a hardcoded SNMP full read-write community string that remains
  active even when SNMP is disabled in the printer management utility.");

  script_tag(name:"solution", value:"Upgrade Samsung Printer to 20121031 or later.");

  script_tag(name:"summary", value:"This host has Samsung Printer firmware and is prone to authentication bypass
  vulnerability.");

  script_tag(name:"affected", value:"Samsung Printers firmware version prior to 20121031

  NOTE: Samsung has stated that models released after October 31, 2012 are not
        affected by this vulnerability. Samsung has also indicated that they
        will be releasing a patch tool later this year to address vulnerable
        devices.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("dump.inc");
include("http_func.inc"); # for make_list_unique

ports = get_kb_list( "Services/udp/snmp" );
if( ! ports ) ports = make_list_unique( 161, 1118 );

function parse_result(data) {

  if(strlen(data) < 8) return FALSE;

  for(v=0; v < strlen(data); v++) {

      if(ord(data[v]) == 43 && ord(data[v-1]) == 8) {
        ok = TRUE;
        break;
      }
      oid_len = ord(data[v]);
  }

  if(!ok || oid_len < 8)return FALSE;

  tmp = substr(data,(v+oid_len+2));

  if (!isprint (c:tmp[0])) {
    tmp = substr(tmp,1,strlen(tmp)-1);
  }

  return tmp;

}

function test(community,port) {

  local_var port, community;

  soc = open_sock_udp(port);
  if(!soc)return FALSE;

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen(community);

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;

  for (i=0; i<3; i++) {

    sendata = raw_string(
                  0x30, 0x82, len_hi, len_lo,
                  0x02, 0x01, i, 0x04,
                  sz);


    sendata = sendata + community +
              raw_string(0xA1,0x18, 0x02,
                  0x01, 0x01, 0x02, 0x01,
                  0x00, 0x02, 0x01, 0x00,
                  0x30, 0x0D, 0x30, 0x82,
                  0x00, 0x09, 0x06, 0x05,
                  0x2B, 0x06, 0x01, 0x02,
                  0x01, 0x05, 0x00);

    send(socket:soc, data:sendata);
    result = recv(socket:soc, length:65535, timeout:1);
    close(soc);

    if(!result || ord(result[0]) != 48)return FALSE;

    if(res = parse_result(data:result)) {
      return res;
    }

  }

  return FALSE;

}

foreach port (ports) {

  if(!get_udp_port_state(port))continue;
  if(get_kb_item("SNMP/" + port + "/v12c/all_communities"))continue; # For devices which are accepting every random community

  res = test(community:'s!a@m#n$p%c',port:port);
  if(!res)continue;

  res = tolower(res);

  if("samsung" >< res || "dell" >< res) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
