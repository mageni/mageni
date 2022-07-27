###############################################################################
# OpenVAS Vulnerability Test
#
# Apache HTTP Server 'mod_md' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813265");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8011");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-20 15:20:23 +0530 (Fri, 20 Jul 2018)");
  script_name("Apache HTTP Server 'mod_md' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with Apache HTTP server
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'mod_md'
  challenge handler.Which is not properly handling the specially crafting HTTP
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to crash the Apache HTTP Server and perform denial of service attack.");

  script_tag(name:"affected", value:"Apache HTTP server version 2.4.33 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.34 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/40");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2018-8011");
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

if(vers == "2.4.33")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.34" , install_path:path);
  security_message(port:hport, data:report);
  exit(0);
}
