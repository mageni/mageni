# OpenVAS Vulnerability Test
# $Id: ftp_kibuv_worm.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: Kibuv worm detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.18367");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kibuv worm detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Malware");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  # nb: Trend says 7955 but I saw it on 14920 and 42260
  script_require_ports("Services/ftp", 7955);
  script_mandatory_keys("ftp/banner/available");

  script_xref(name:"URL", value:"http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=WORM_KIBUV.B&VSect=T");

  script_tag(name:"solution", value:"Patch your system and run an antivirus.");

  script_tag(name:"summary", value:"A fake FTP server was installed by the KIBUV.B worm
  on this port. This worm uses known security flaws to infect the system.

  This machine may already be a 'zombi' used by attackerss
  to perform distributed denial of service.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include('ftp_func.inc');

port = get_ftp_port(default:7955);
b = get_ftp_banner(port: port);
if(!b)
  exit(0);

if ('220 StnyFtpd 0wns j0' >< b ||
    # I also saw that banner, I guess this is a variant
    '220 fuckFtpd 0wns j0' >< b)
{
  set_kb_item(name: 'ftp/'+port+'/backdoor', value: 'KIBUV.B');
  set_kb_item(name: 'ftp/backdoor', value: 'KIBUV.B');
  security_message(port);
}
