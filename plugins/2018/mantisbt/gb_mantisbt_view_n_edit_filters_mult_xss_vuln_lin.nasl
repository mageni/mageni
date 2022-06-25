###############################################################################
# OpenVAS Vulnerability Test
#
# MantisBT 'View Filters' And 'Edit Filter' Pages XSS Vulnerabilities
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813814");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-14504", "CVE-2018-13055");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-06 18:05:16 +0530 (Mon, 06 Aug 2018)");
  script_name("MantisBT 'View Filters' And 'Edit Filter' Pages XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with MantisBT and is
  prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input validation error in Edit Filter page(manage_filter_edit_page.php).

  - An input validation error for PATH_INFO in the View Filters page
    (view_filters_page.php).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"MantisBT version 2.1.0 through 2.15.0 on Linux.");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 2.15.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://mantisbt.org/blog/archives/mantisbt/602");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=24608");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=24580");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:manPort, exit_no_version:TRUE)) exit(0);
manVer = infos['version'];
path = infos['location'];

if(version_in_range(version:manVer, test_version:"2.1.0", test_version2:"2.15.0"))
{
  report = report_fixed_ver(installed_version: manVer, fixed_version: "2.15.1", install_path:path);
  security_message(port: manPort, data: report);
  exit(0);
}
