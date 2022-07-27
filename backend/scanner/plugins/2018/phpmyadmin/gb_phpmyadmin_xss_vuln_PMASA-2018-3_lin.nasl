###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Cross-Site Scripting Vulnerability (PMASA-2018-3)-Linux
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
  script_oid("1.3.6.1.4.1.25623.1.0.813451");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12581");
  script_bugtraq_id(104530);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 15:47:09 +0530 (Tue, 26 Jun 2018)");
  script_name("phpMyAdmin Cross-Site Scripting Vulnerability (PMASA-2018-3)-Linux");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin and
  is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient validation
  of input passed to 'js/designer/move.js' script in phpMyAdmin.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary web script or HTML via crafted database name.");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 4.8.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 4.8.2 or newer. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-3");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide", "phpMyAdmin/installed");
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

if(version_is_less(version:vers, test_version:"4.8.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);
