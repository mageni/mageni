###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_server_dos_vuln_jul16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Apache HTTP Server Denial of Service Vulnerability - Jul16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807854");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-1546");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-08 18:36:25 +0530 (Fri, 08 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server Denial of Service Vulnerability - Jul16");

  script_tag(name:"summary", value:"This host is installed with Apache HTTP Server
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as application does not restrict
  number of concurrent stream workers per connection.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.4.17 and 2.4.18,
  when mod_http2 is enabled");

  script_tag(name:"solution", value:"Upgrade to version 2.4.20 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}

## For when mod_http2 and mod_ssl are enabled --> using qod as remote_banner_unreliable
if(version_in_range(version:httpd_ver, test_version:"2.4.17", test_version2:"2.4.18"))
{
  report = report_fixed_ver(installed_version:httpd_ver, fixed_version:"2.4.20");
  security_message(data:report, port:httpd_port);
  exit(0);
}
