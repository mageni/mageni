###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_mult_xss_vuln01.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities-01
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809850");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2016-5124");
  script_bugtraq_id(91775);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-02 15:30:00 +0530 (Mon, 02 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities-01");

  script_tag(name:"summary", value:"The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper
  sanitization of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in the browser of an unsuspecting user in the
  context of the affected application. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versions
  7.6.2-rev0 - 7.6.2-rev54,
  7.6.3-rev0 - 7.6.3-rev12,
  7.8.0-rev0 - 7.8.0-rev31,
  7.8.1-rev0 - 7.8.1-rev13");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.8.1-rev14, or 7.6.2-rev55, or 7.6.3-rev13, or 7.8.0-rev32, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036296");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/137894");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.open-xchange.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!oxPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!oxVer = get_app_version(cpe:CPE, port:oxPort)){
  exit(0);
}

oxRev = get_kb_item("open_xchange_appsuite/" + oxPort + "/revision");

if(oxRev && oxVer)
{
  ## Updating version with revision number
  oxVer = oxVer + "." + oxRev;

  if(oxVer =~ "^(7\.8\.1)" && version_is_less( version:oxVer, test_version:"7.8.1.14"))
  {
    fix = "7.8.1-rev14";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.6\.2)" && version_is_less( version:oxVer, test_version:"7.6.2.55"))
  {
    fix = "7.6.2-rev55";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.6\.3)" && version_is_less( version:oxVer, test_version:"7.6.3.13"))
  {
    fix = "7.6.3-rev13";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.8\.0)" && version_is_less( version:oxVer, test_version:"7.8.0.32"))
  {
    fix = "7.8.0-rev32";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:oxVer, fixed_version:fix);
    security_message(port:oxPort, data:report);
    exit(0);
  }
}

exit(99);