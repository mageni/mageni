##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_mult_dos_vuln_april16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Squid Multiple Denial of Service Vulnerabilities April16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807793");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-3947", "CVE-2016-3948");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 18:23:23 +0530 (Mon, 18 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Squid Multiple Denial of Service Vulnerabilities April16 (Windows)");

  script_tag(name:"summary", value:"This host is running Squid and is prone
  to multiple denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A buffer overrun in the 'Icmp6::Recv' function in 'icmp/Icmp6.cc' script
    in the 'pinger' process.

  - An incorrect bounds checking while processing HTTP responses.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  HTTP servers to cause a denial of service, or write sensitive information to
  log files.");

  script_tag(name:"affected", value:"Squid version 3.x before 3.5.16 and 4.x
  before 4.0.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Squid version 3.5.16 or 4.0.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-3948");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-3947");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_4.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_3.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid_proxy_server/installed", "Host/runs_windows");
  script_require_ports("Services/www", 3128, 8080);
  script_xref(name:"URL", value:"http://www.squid-cache.org");
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

if(squidVer =~ "^(3|4)")
{
  if(version_in_range(version:squidVer, test_version:"3.0.0", test_version2:"3.5.15"))
  {
    fix = "3.5.16";
    VULN = TRUE ;
  }

  else if(version_in_range(version:squidVer, test_version:"4.0.0", test_version2:"4.0.7"))
  {
    fix = "4.0.8";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:squidVer, fixed_version:fix);
    security_message(data:report, port:squidPort);
    exit(0);
  }
}
