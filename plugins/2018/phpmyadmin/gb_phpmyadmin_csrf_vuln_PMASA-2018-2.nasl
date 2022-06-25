###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Cross-Site Request Forgery Vulnerability-PMASA-2018-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.813158");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10188");
  script_bugtraq_id(103936);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-02 17:13:20 +0530 (Wed, 02 May 2018)");
  script_name("phpMyAdmin Cross-Site Request Forgery Vulnerability-PMASA-2018-2");

  script_tag(name:"summary", value:"The host is installed with phpMyAdmin and
  is prone to cross site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to failure in the
  '/sql.php' script to properly verify the source of HTTP request.");

  script_tag(name:"impact", value:"Successful exploitation of this cross-site
  request forgery (CSRF) allows an attacker to execute arbitrary SQL statement
  by sending a malicious request to a logged in user.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.8.0");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.8.0-1 or
  newer version or apply patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  ##unreliable as Patch is also available as solution
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-2/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44496/");
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

if(vers == "4.8.0")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.0-1", install_path:path);
  security_message( port:phport, data:report);
  exit(0);
}
exit(0);
