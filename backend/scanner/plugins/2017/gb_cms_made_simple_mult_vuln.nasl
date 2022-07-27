###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# CMS Made Simple 2.2.3.1 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112119");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-13 13:56:33 +0100 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-16798", "CVE-2017-16799");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple 2.2.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CMS Made Simple is prone to multiple vulnerabilities:

  - The is_file_acceptable function in modules/FileManager/action.upload.php only blocks file extensions that begin or end with a 'php' substring,
which allows remote attackers to bypass intended access restrictions or trigger XSS via other extensions, as demonstrated by .phtml, .pht, .html, or .svg. (CVE-2017-16798)

  - In modules/New/action.addcategory.php, stored XSS is possible via the m1_name parameter to admin/moduleinterface.php during addition of a category,
a related issue to CVE-2010-3882. (CVE-2017-16799)");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.3.1.");

  script_tag(name:"solution", value:"Upgrade to CMS Made Simple version 2.2.4 or above.");

  script_xref(name:"URL", value:"https://github.com/bsmali4/cve/blob/master/CMS%20Made%20Simple%20Stored%20XSS.md");
  script_xref(name:"URL", value:"https://github.com/bsmali4/cve/blob/master/CMS%20Made%20Simple%20UPLOAD%20FILE%20XSS.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.2.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
