# OpenVAS Vulnerability Test
# $Id: snapstream_dir_trav.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Snapstream PVS web directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11079");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3100);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1108");
  script_name("Snapstream PVS web directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8129);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or change it!");

  script_tag(name:"summary", value:"It is possible to read arbitrary files on the remote
  Snapstream PVS server by prepending ../../ in front on the file name.

  It may also be possible to read ../ssd.ini which contains many information on the
  system (base directory, usernames & passwords).");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8129);

files = make_list( "/../ssd.ini", "/../../../../autoexec.bat", "/../../../winnt/repair/sam" );

foreach file(files) {
  ok = is_cgi_installed_ka(port:port, item:file);
  if(ok){
    report = report_vuln_url(port:port, url:file);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);