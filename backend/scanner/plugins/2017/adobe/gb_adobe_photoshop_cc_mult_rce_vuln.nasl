###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop CC Multiple Remote Code Execution Vulnerabilities (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:photoshop_cc2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812210");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-11304", "CVE-2017-11303");
  script_bugtraq_id(101829);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-16 16:38:07 +0530 (Thu, 16 Nov 2017)");
  script_name("Adobe Photoshop CC Multiple Remote Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to a memory
  corruption error and an use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application and gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 18.1.1 (2017.1.1)
  and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017
  18.1.2 (2017.1.2) or Photoshop CC 2018 19.0 (2018.0) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-34.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
prodVer2017 = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:prodVer2017, test_version:"18.1.1"))
{
  report = report_fixed_ver( installed_version:"CC 2017 " + prodVer2017, fixed_version:"CC 2017 18.1.2 or CC 2018 19.0", install_path:path );
  security_message(data:report);
}
exit(0);
