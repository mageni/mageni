###############################################################################
# OpenVAS Vulnerability Test
#
# Apache HTTP Server Denial of Service Vulnerability Apr18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812850");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-1302");
  script_bugtraq_id(103528);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-02 16:48:45 +0530 (Mon, 02 Apr 2018)");
  script_name("Apache HTTP Server Denial of Service Vulnerability Apr18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Apache HTTP server
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the Apache HTTP Server
  writes a NULL pointer potentially to an already freed memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to destroy an HTTP/2 stream, resulting in a denial of service condition.");

  script_tag(name:"affected", value:"Apache HTTP server versions 2.4.17, 2.4.18,
  2.4.20, 2.4.23 and from 2.4.25 to 2.4.29 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.30 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://httpd.apache.org/download.cgi");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2018/03/24/8");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2018/03/24/2");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_windows", "apache/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:hport, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

affected = make_list("2.4.17", "2.4.18", "2.4.20", "2.4.23", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29");

if(version_in_range(version:vers, test_version:"2.4.17", test_version2:"2.4.29"))
{
  foreach version (affected)
  {
    if(vers == version)
    {
      report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.30" , install_path:path);
      security_message(port:hport, data:report);
      exit(0);
    }
  }
}
exit(0);
