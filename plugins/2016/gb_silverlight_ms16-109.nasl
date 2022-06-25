###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Silverlight Remote Code Execution Vulnerability (3182373)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809309");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3367");
  script_bugtraq_id(92837);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 08:56:33 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerability (3182373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3182373");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-109");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-109.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due when Microsoft
  Silverlight improperly allows applications to access objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation could corrupt system
  memory, which could allow an attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5 on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_is_less(version:msl_ver, test_version:"5.1.50709.0"))
  {
    report = 'Silverlight version: ' + msl_ver  + '\n' +
             'Vulnerable range:    5.0 - 5.1.50708.0';
    security_message(data:report);
    exit(0);
  }
}
