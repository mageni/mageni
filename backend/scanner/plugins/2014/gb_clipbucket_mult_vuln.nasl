###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipbucket_mult_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# ClipBucket Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:clipbucket_project:clipbucket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804543");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2012-6642", "CVE-2012-6643", "CVE-2012-6644");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-18 12:23:11 +0530 (Fri, 18 Apr 2014)");
  script_name("ClipBucket Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ClipBucket and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not.");
  script_tag(name:"insight", value:"Input passed via multiple parameters to multiple scripts is not properly
  sanitised before being returned to the user. For more information please
  check the Reference section");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"ClipBucket version 2.6, Other versions may also be affected.");
  script_tag(name:"solution", value:"Apply the patch from the referenced link.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47474");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108489");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");
  script_require_ports("Services/www", 80);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/clipbucket/files/ClipBucket%20v2");
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + "/videos.php?cat=all&seo_cat_name=&sort=most_recent&time=1%27SQL-Injection-Test";

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
exit(99);
