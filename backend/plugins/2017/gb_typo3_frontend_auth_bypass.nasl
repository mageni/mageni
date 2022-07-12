###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_frontend_auth_bypass.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# TYPO3 Frontend Authentication Bypass Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107238");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 22:06:49 +0200 (Fri, 08 Sep 2017)");
  script_bugtraq_id(96501);

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("TYPO3 Frontend Authentication Bypass Vulnerability");
  script_tag(name:"summary", value:"TYPO3 is prone to an authentication-bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
  mechanism and obtain sensitive information. This may aid in further attacks.");
  script_tag(name:"affected", value:"TYPO3 versions 8.2.0 through 8.6.0 are vulnerable");
  script_tag(name:"solution", value:"Update to TYPO3 version 8.6.1.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96501");
  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2017-002/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")){
  exit(0);
}

if(Ver =~ "^8")
{
  if(version_in_range(version:Ver, test_version:"8.2.0", test_version2:"8.6.0"))
  {
    fix = "8.6.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit ( 99 );

