###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_unspecified_remote_dos_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# HPE LoadRunner Unspecified Remote DoS Vulnerability
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810934");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-4384");
  script_bugtraq_id(93069);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 16:22:23 +0530 (Thu, 20 Apr 2017)");
  script_name("HPE LoadRunner Unspecified Remote DoS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to a remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"HPE LoadRunner versions prior to 12.50
  patch 3");

  script_tag(name:"solution", value:"Upgrade to HPE LoadRunner version
  12.50 patch 3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05278882");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## no version change after applying patch
## 12.50 patch 3 also will be reported as vulnerabe
## qod is reduced
## HPSBGN03648 says that "all versions prior to v12.50" are affected meaning 12.50
## is the fix. But next then say 12.50 patch 3 is the fix meaning 12.50 is vulnerable.
if(version_is_less_equal(version:hpVer, test_version:"12.50"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"12.50 patch 3");
  security_message(data:report);
  exit(0);
}
