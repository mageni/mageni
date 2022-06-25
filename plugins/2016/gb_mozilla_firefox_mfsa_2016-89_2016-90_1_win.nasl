###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2016-89_2016-90_1_win.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Mozilla Firefox Security Updates( mfsa_2016-89_2016-90 )-Windows
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

CPE = "cpe:/a:mozilla:firefox:x64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809809");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-9072");
  script_bugtraq_id(94336);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-16 12:21:41 +0530 (Wed, 16 Nov 2016)");
  script_name("Mozilla Firefox Security Updates (mfsa_2016-89_2016-90)-Windowsx64");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to,
  64-bit NPAPI sandbox is not enabled on fresh profile.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  50 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 50
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver", "SMB/Windows/Arch");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!osArch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

## if not 64bit arch, exit.
if("x64" >!< osArch){
  exit(0);
}

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"50.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"50.0");
  security_message(data:report);
  exit(0);
}
