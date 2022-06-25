###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_may14_macosx.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Adobe Acrobat Multiple Vulnerabilities - 01 May14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804605");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-0521", "CVE-2014-0522", "CVE-2014-0523", "CVE-2014-0524",
                "CVE-2014-0525", "CVE-2014-0526", "CVE-2014-0527", "CVE-2014-0528",
                "CVE-2014-0529");
  script_bugtraq_id(67363, 67360, 67368, 67369, 67365, 67370, 67367, 67366, 67362);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-22 11:36:32 +0530 (Thu, 22 May 2014)");
  script_name("Adobe Acrobat Multiple Vulnerabilities - 01 May14 (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1030229");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14051403");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-15.html");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists,

  - An error within the implementation of Javascript APIs.

  - An error when validating user supplied paths.

  - An integer overflow error when handling PDF417 barcodes.

  - An error exists within the handling of certain API calls to unmapped memory.

  - A use-after-free error when handling the messageHandler property of the
  AcroPDF ActiveX control.

  - A double-free error.

  - Many other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a denial of service,
  disclose potentially sensitive information, bypass certain security
  restrictions, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat X before version 10.1.10 and XI before version 11.0.07 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat X version 10.1.10 or XI version 11.0.07 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!acroVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(acroVer && acroVer =~ "^1[01]"){
  if(version_in_range(version:acroVer, test_version:"10.0.0", test_version2:"10.1.09")||
     version_in_range(version:acroVer, test_version:"11.0.0", test_version2:"11.0.06")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);