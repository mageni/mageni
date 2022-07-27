###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Security Bypass Vulnerability-PMASA-2017-8
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813163");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-18264");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-03 12:01:22 +0530 (Thu, 03 May 2018)");
  script_name("phpMyAdmin Security Bypass Vulnerability-PMASA-2017-8");

  script_tag(name:"summary", value:"The host is installed with phpMyAdmin and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where the
  restrictions created for accounts with no password and 'AllowNoPassword' is
  set to false, are bypassed under certain PHP versions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security measures and do login of users who have no password set.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.0 prior to 4.0.10.20,
  4.4.x, 4.6.x, 4.7.0-beta1 and 4.7.0-rc1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.20 or
  4.7.0 or newer or apply patch as provided by vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  ##unreliable as Patch, mitigation is also available as solution
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-8");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!(phport = get_app_port(cpe: CPE))){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:phport, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers == "4.7.0-rc1" || vers == "4.7.0-beta1" || vers =~ "^(4.\(6|4))"){
  fix = "4.7.0";
} else if(version_in_range(version: vers, test_version: "4.0", test_version2: "4.0.10.19")){
  fix = "4.0.10.20";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:phport, data:report);
  exit(0);
}
exit(0);
