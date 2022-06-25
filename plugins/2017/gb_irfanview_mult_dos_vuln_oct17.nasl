###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irfanview_mult_dos_vuln_oct17.nasl 12154 2018-10-29 15:06:04Z mmartin $
#
# IrfanView Multiple DoS Vulnerabilities Oct17
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

CPE = "cpe:/a:irfanview:irfanview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811954");
  script_version("$Revision: 12154 $");
  script_cve_id("CVE-2017-14540", "CVE-2017-14539", "CVE-2017-14693");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 16:06:04 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-26 11:40:33 +0530 (Thu, 26 Oct 2017)");
  script_name("IrfanView Multiple DoS Vulnerabilities Oct17");

  script_tag(name:"summary", value:"This host is installed with IrfanView and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exits due to
  data from faulting address controls branch selection starts at
  particular point.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"IrfanView Version 4.44 32bit version only");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_mandatory_keys("IrfanView/Ver");
  script_exclude_keys("IrfanView/Ver/x64");
  script_xref(name:"URL", value:"http://www.irfanview.com/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!irfVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:irfVer, test_version:"4.44"))
{
  report = report_fixed_ver(installed_version:irfVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
