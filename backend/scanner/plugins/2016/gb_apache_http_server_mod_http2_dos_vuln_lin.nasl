###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_http_server_mod_http2_dos_vuln_lin.nasl 12153 2018-10-29 13:38:34Z cfischer $
#
# Apache HTTP Server 'mod_http2' Denial of Service Vulnerability (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810303");
  script_version("$Revision: 12153 $");
  script_cve_id("CVE-2016-8740");
  script_bugtraq_id(94650);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 14:38:34 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-06 18:47:46 +0530 (Tue, 06 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server 'mod_http2' Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache HTTP Server
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the 'mod_http2' module,
  when the Protocols configuration includes h2 or h2c, does not restrict
  request header length");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.4.17 through 2.4.23
  on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.apache.org/security/asf-httpoxy-response.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://github.com/apache/httpd/commit/29c63b786ae028d82405421585e91283c8fa0da3");
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

if(httpd_ver =~ "^2\.4")
{
  if(version_in_range(version:httpd_ver, test_version:"2.4.17", test_version2:"2.4.23"))
  {
    report = report_fixed_ver(installed_version:httpd_ver, fixed_version:"Apply the patch");
    security_message(data:report, port:httpd_port);
    exit(0);
  }
}
