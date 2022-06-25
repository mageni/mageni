###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_dos_n_deserial_vuln_win.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Struts 'REST' Plugin Deserialization And DoS Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812320");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-15707", "CVE-2017-7525");
  script_bugtraq_id(102021, 99623);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-05 11:36:43 +0530 (Tue, 05 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Struts 'REST' Plugin Deserialization And DoS Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to de-serialization and denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in 'REST' plugin which is using an outdated JSON-lib library and is
    not handling malicious request with specially crafted JSON payload properly.

  - An error in the latest Jackson JSON library.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform a DoS attack or execute arbitrary code in the context of the affected
  application.");

  script_tag(name:"affected", value:"Apache Struts Version 2.5 through 2.5.14
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.5.14.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-054");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-055");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://struts.apache.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:appPort, exit_no_version:TRUE)) exit(0);
appVer = infos['version'];
appPath = infos['location'];

if(appVer =~ "^(2\.)")
{
  if(version_in_range(version:appVer, test_version:"2.5", test_version2:"2.5.14"))
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version: "2.5.14.1", install_path:appPath);
    security_message(port:appPort, data: report);
    exit(0);
  }
}
exit(0);
