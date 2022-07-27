###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_bbcode_injection_vuln01_july16_lin.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# phpMyAdmin BBCode Injection Vulnerability -01 July16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808243");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-5701");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 14:45:45 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("phpMyAdmin BBCode Injection Vulnerability -01 July16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to BBCode injection attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied input via URI in 'setup/frames/index.inc.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct BBCode injection attacks against HTTP sessions.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.10.x before 4.0.10.16,
  4.4.15.x before 4.4.15.7, and 4.6.x before 4.6.3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.16 or
  4.4.15.7 or 4.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-17");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!phpPort = get_app_port(cpe:CPE)) exit(0);

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

if(phpVer =~ "^(4\.0\.10)")
{
  if(version_is_less(version:phpVer, test_version:"4.0.10.16"))
  {
    fix = "4.0.10.16";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.4\.15)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.15.7"))
  {
    fix = "4.4.15.7";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.6)")
{
  if(version_is_less(version:phpVer, test_version:"4.6.3"))
  {
    fix = "4.6.3";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}
