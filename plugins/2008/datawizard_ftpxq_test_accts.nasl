##############################################################################
# OpenVAS Vulnerability Test
# $Id: datawizard_ftpxq_test_accts.nasl 13476 2019-02-05 15:05:10Z cfischer $
#
# Tries to read a file via FTPXQ.
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80053");
  script_version("$Revision: 13476 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 16:05:10 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2006-5569");
  script_bugtraq_id(20721);
  script_name("DataWizard FTPXQ Default Accounts");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2006 Justin Seitz");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ftpxq/detected");

  script_tag(name:"solution", value:"Disable or change the password for any unnecessary user accounts.");

  script_tag(name:"summary", value:"The version of DataWizard FTPXQ that is installed on the remote host
  has one or more default accounts setup which can allow an attacker to read and/or write arbitrary files on the system.");

  script_xref(name:"URL", value:"http://attrition.org/pipermail/vim/2006-November/001107.html");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ftp_func.inc");

port   = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( ! banner || "FtpXQ FTP" >!< banner )
  exit( 0 );

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

n = 0;
acct[n] = "anonymous";
pass[n] = "";
n++;
acct[n] = "test";
pass[n] = "test";

file = '\\boot.ini';
contents = "";
info = "";
for (i=0; i<max_index(acct); i++) {
  login = acct[i];
  password = pass[i];

  if (ftp_authenticate(socket:soc, user:login, pass:password)) {
    info += "  " + login + "/" + password + '\n';

    if (strlen(contents) == 0) {
      #	We have identified that we have logged in with the account, let's try to read boot.ini.
      port2 = ftp_pasv(socket:soc);
      if (!port2) exit(0);
      soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
      if (!soc2) exit(0);

      attackreq = string("RETR ", file);
      send(socket:soc, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_line(socket:soc);
      if (egrep(string:attackres, pattern:"^(425|150) ")) {
        attackres2 = ftp_recv_data(socket:soc2);

        # There's a problem if it looks like a boot.ini.
        if ("[boot loader]" >< attackres2)
          contents = attackres2;
      }
    }
  }
}

if (info) {
  info = string("The remote version of FTPXQ has the following\n",
    "default accounts enabled :\n\n",
    info);

  if ("test/test" >< info)
    info = string(info, "\n",
      "Note that the test account reportedly allows write access to the entire\n",
      "filesystem, although the scanner did not attempt to verify this.\n");

  if (contents)
    info = string(info, "\n",
      "In addition, the scanner was able to use one of the accounts to read ", file, " :\n",
      "\n",
      contents);

  security_message(data:info, port:port);
}
ftp_close(socket:soc);
