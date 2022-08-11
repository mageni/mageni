###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_preauth_ssrf_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# vBulletin Preauth Server Side Request Forgery (SSRF) Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809158");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-6483");
  script_bugtraq_id(92350);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-29 14:43:57 +0530 (Mon, 29 Aug 2016)");
  script_name("vBulletin Preauth Server Side Request Forgery (SSRF) Vulnerability");

  script_tag(name:"summary", value:"This host is installed with vBulletin and is prone
  to server side request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a codebase accepts HTTP
  redirects from the target server specified in a user-provided link.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  unauthenticated remote attackers to bypass certain security restrictions to
  perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"vBulletin versions 5.0 through 5.2.2,
  and 4.0 through 4.2.3, and 3.0 through 3.8.9");

  script_tag(name:"solution", value:"Upgrade to vBulletin version 5.2.3,
  or 4.2.4 Beta, or 3.8.10 Beta, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Aug/68");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.vbulletin.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vVer = get_app_version(cpe:CPE, port:vPort)){
  exit(0);
}

if(version_in_range(version:vVer, test_version:"5.0.0", test_version2:"5.2.2"))
{
  fix = '5.2.3';
  VULN = TRUE;
}

else if(version_in_range(version:vVer, test_version:"4.0.0", test_version2:"4.2.3"))
{
  fix = '4.2.4 Beta';
  VULN = TRUE;
}

else if(version_in_range(version:vVer, test_version:"3.0.0", test_version2:"3.8.9"))
{
  fix = '3.8.10 Beta';
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vVer, fixed_version:fix);
  security_message(data:report, port:vPort);
  exit(0);
}
