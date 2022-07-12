###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_asset_explorer_mult_xss_vuln.nasl 2015-06-24 14:40:38 +0530 Jun$
#
# Manage Engine Asset Explorer Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:zohocorp:manageengine_assetexplorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805707");
  script_version("$Revision: 13213 $");
  script_cve_id("CVE-2015-5061", "CVE-2015-2169");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 11:23:57 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-06-24 14:40:38 +0530 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Manage Engine Asset Explorer Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Manage Engine Asset
  Explorer and is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple Flaws are due to

  - The 'VendorDef.do' script does not validate input to vendor name field before returning it to users.

  - Publisher registry entry script does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"ManageEngine AssetExplorer version 6.1.0 Build 6112 and prior.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine AssetExplorer version 6.1.0 build 6113 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jun/60");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1488");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_asset_explorer_detect.nasl");
  script_mandatory_keys("manageengine/assetexplorer/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!assetPort = get_app_port(cpe:CPE))
  exit(0);

if (!assetVer = get_app_version(cpe:CPE, port:assetPort))
  exit(0);

if(version_is_less(version:assetVer, test_version:"6.1.0")) {
  report = report_fixed_ver(installed_version: assetVer, fixed_version: "6.1.0 Build 6113");
  security_message(data:report, port:assetPort);
  exit(0);
}

assetBuild = get_kb_item("manageengine/assetexplorer/build");

if (assetBuild) {
  if ((version_is_equal(version:assetVer, test_version:"6.1.0")) &&
      (version_is_less(version:assetBuild, test_version:"6113"))) {
    report = report_fixed_ver(installed_version: assetVer, installed_build: assetBuild,
                              fixed_version: "6.1.0", fixed_build: "6113");
    security_message(data:report, port:assetPort);
    exit(0);
  }
}

exit(99);
