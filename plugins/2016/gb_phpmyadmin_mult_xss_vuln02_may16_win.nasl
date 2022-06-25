###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_xss_vuln02_may16_win.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# phpMyAdmin Multiple XSS Vulnerabilities -02 May16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807597");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-2560");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-17 12:12:08 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("phpMyAdmin Multiple XSS Vulnerabilities -02 May16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input validation error via Host HTTP header, related to
    'libraries/Config.class.php' script.

  - An input validation error via JSON data, related to 'file_echo.php' script.

  - An input validation error related to SQL query in 'js/functions.js script'.

  - An input validation error via the initial parameter to
    'libraries/server_privileges.lib.php' script in the user accounts page.

  - An input validation error via a parameter to
    'libraries/controllers/TableSearchController.class.php' script in the
    zoom search page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via crafted parameters.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.x before 4.0.10.15,
  4.4.x before 4.4.15.5, and 4.5.x before 4.5.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.15 or
  4.4.15.5 or 4.5.5.1 or later or apply patch from the link mentioned in reference.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-11");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("http_func.inc");


if(!phpPort = get_app_port(cpe:CPE)) exit(0);

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

if(phpVer =~ "^(4\.0)")
{
  if(version_is_less(version:phpVer, test_version:"4.0.10.15"))
  {
    fix = "4.0.10.15";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.5)")
{
  if(version_is_less(version:phpVer, test_version:"4.5.5.1"))
  {
    fix = "4.5.5.1";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.4)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.15.5"))
  {
    fix = "4.4.15.5";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}
