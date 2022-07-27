###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Cross-Site Scripting Vulnerability(PMASA-2018-1)-Windows
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812812");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-7260");
  script_bugtraq_id(103099);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-28 11:56:43 +0530 (Wed, 28 Feb 2018)");
  script_name("phpMyAdmin Cross-Site Scripting Vulnerability(PMASA-2018-1)-Windows");

  script_tag(name:"summary", value:"The host is installed with phpMyAdmin and
  is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an invalidated
  variable total_rows of db_central_columns.php page");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary web script or HTML via a crafted URL.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.7.x prior to 4.7.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 4.7.8 or later..");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-1");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_phpmyadmin_detect_900129.nasl");
  script_mandatory_keys("Host/runs_windows", "phpMyAdmin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^(4\.7)" && version_is_less(version:vers, test_version:"4.7.8"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.7.8", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);
