###############################################################################
# OpenVAS Vulnerability Test
#
# Open-Xchange (OX) AppSuite SVG File Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806076");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2014-1679");
  script_bugtraq_id(65500);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-07 10:16:00 +0530 (Wed, 07 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite SVG File Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with
  Open-Xchange (OX) AppSuite and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  sanitization of user supplied input via the header in an attached SVG file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject arbitrary web script or HTML leading to session hijacking or
  triggering unwanted actions via the web interface.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versins before
  7.2.2-rev31, 7.4.0 before 7.4.0-rev27, and 7.4.1 before 7.4.1-rev17");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.2.2-rev31 or 7.4.0-rev27 or 7.4.1-rev17 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/531005");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!oxPort = get_app_port(cpe:CPE)){
  exit(0);
}

oxVer = get_app_version(cpe:CPE, port:oxPort);
if(!oxVer || "unknown" >< oxVer){
  exit(0);
}

oxRev = get_kb_item("open_xchange_appsuite/" + oxPort + "/revision");

if(oxRev)
{

  ## Updating version with revision number
  oxVer = oxVer + "." + oxRev;

  if(version_is_less(version:oxVer, test_version:"7.2.2.31"))
  {
    fix = "7.2.2-rev31";
    VULN = TRUE;
  }

  if(version_in_range(version:oxVer, test_version:"7.4.0", test_version2:"7.4.0.26"))
  {
    fix = "7.4.0-rev27";
    VULN = TRUE;
  }

  if(version_in_range(version:oxVer, test_version:"7.4.1", test_version2:"7.4.1.16"))
  {
    fix = "7.4.1-rev17";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed Version: ' + oxVer + '\nFixed Version:     ' + fix + '\n';
    security_message(port:oxPort, data:report);
    exit(0);
  }
}

exit(99);