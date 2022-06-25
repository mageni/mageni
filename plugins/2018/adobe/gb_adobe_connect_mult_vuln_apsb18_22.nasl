###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Connect Multiple Vulnerabilities (APSB18-22)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813659");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-4994", "CVE-2018-12804", "CVE-2018-12805");
  script_bugtraq_id(104102, 104697, 104696);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-12 10:36:00 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities (APSB18-22)");

  script_tag(name:"summary", value:"The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An insecure library loading error.

  - Multiple authentication bypass errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct session hijacking, escalate privileges, disclose sensitive
  information.");

  script_tag(name:"affected", value:"Adobe Connect versions 9.7.5 and earlier");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.8.1 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb18-22.html");
  script_xref(name:"URL", value:"http://www.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:acPort, exit_no_version:TRUE)) exit(0);
acVer = infos['version'];
acPath = infos['location'];

if(version_is_less(version:acVer, test_version:"9.8.1"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.8.1", install_path:acPath);
  security_message(data:report, port:acPort);
  exit(0);
}
exit(0);
