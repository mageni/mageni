##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_denial_of_service_vuln_march16_lin.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Squid 'http.cc' Denial of Service Vulnerability (Linux)
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807453");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-2572");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-03 11:34:15 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid 'http.cc' Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Squid and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'http.cc'
  script relies on the HTTP status code after a response-parsing failure.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  HTTP servers to cause a denial of service.");

  script_tag(name:"affected", value:"Squid version 4.x before 4.0.7 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Squid version 4.0.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-2572");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_2.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid_proxy_server/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 3128, 8080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!squidPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!squidVer = get_app_version(cpe:CPE, port:squidPort)){
  exit(0);
}

if(squidVer =~ "^4\.")
{
  if(version_in_range(version:squidVer, test_version:"4.0.0", test_version2:"4.0.6"))
  {
    report = report_fixed_ver(installed_version:squidVer, fixed_version:"4.0.7");
    security_message(data:report, port:squidPort);
    exit(0);
  }
}
