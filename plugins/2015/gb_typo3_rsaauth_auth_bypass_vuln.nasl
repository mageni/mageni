###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_rsaauth_auth_bypass_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# TYPO3 'rsaauth' extension Authentication Bypass Vulnerability (SA-2015-001)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805295");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2015-2047");
  script_bugtraq_id(72763);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-02 18:06:26 +0530 (Mon, 02 Mar 2015)");
  script_name("TYPO3 'rsaauth' extension Authentication Bypass Vulnerability (SA-2015-001)");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is in the system extension
  frontend in rsaauth that is triggered when handling logins");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to authenticate as a frontend user whose login name is known.");

  script_tag(name:"affected", value:"TYPO3 versions 4.3.0 through 4.3.14, 4.4.0
  through 4.4.15, 4.5.0 through 4.5.39, and 4.6.0 through 4.6.18");

  script_tag(name:"solution", value:"For 4.5.x series upgrade to TYPO3 version
  4.5.40 or later, for 4.3.x, 4.4.x and 4.6.x apply the patch as provided in the referenced vendor bulletin.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://review.typo3.org/#/c/37013");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-001");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!typoVer = get_app_version(cpe:CPE, port:typoPort)){
  exit(0);
}

if(typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+") exit(0); # Version is not exact enough

if(typoVer =~ "^(4\.5)")
{
  fix = "4.5.40";
  VULN = TRUE;
}

if(typoVer =~ "^(4\.(3|4|6))")
{
  fix = "Apply Patch";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:fix);
  security_message(port:typoPort, data:report);
  exit(0);
}

exit(99);