###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_dec14_win.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Adobe Acrobat Multiple Vulnerabilities-01 Dec14 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805302");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-9150", "CVE-2014-9165", "CVE-2014-8445", "CVE-2014-8446",
                "CVE-2014-8447", "CVE-2014-8448", "CVE-2014-8449", "CVE-2014-8451",
                "CVE-2014-8452", "CVE-2014-8453", "CVE-2014-8454", "CVE-2014-8455",
                "CVE-2014-8456", "CVE-2014-8457", "CVE-2014-8458", "CVE-2014-8459",
                "CVE-2014-8461", "CVE-2014-9158", "CVE-2014-9159", "CVE-2014-8460");
  script_bugtraq_id(71366, 71575, 71561, 71570, 71574, 71564, 71568, 71565, 71567,
                    71557, 71562, 71571, 71572, 71566, 71573, 71576, 71578, 71577,
                    71580, 71579);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-11 17:25:05 +0530 (Thu, 11 Dec 2014)");

  script_name("Adobe Acrobat Multiple Vulnerabilities-01 Dec14 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - Multiple use-after-free errors can be exploited to execute arbitrary code.

  - Multiple unspecified errors can be exploited to cause a heap-based buffer overflow
    and subsequently execute arbitrary code.

  - A Race condition in the MoveFileEx call hook feature allows attackers to
    bypass a sandbox protection mechanism.

  - An error within the implementation of a Javascript API can be exploited to disclose
    certain information.

  - Multiple integer overflow errors can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to disclose potentially sensitive information, bypass certain
  security restrictions, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat 10.x before 10.1.13 and Adobe
  Acrobat 11.x before 11.0.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 10.1.13 or
  11.0.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://secunia.com/advisories/61095/");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-28.html");
  script_xref(name:"URL", value:"https://code.google.com/p/google-security-research/issues/detail?id=103");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!acroVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(acroVer && acroVer =~ "^(10|11)")
{
  if(version_in_range(version:acroVer, test_version:"10.0.0", test_version2:"10.1.12")||
     version_in_range(version:acroVer, test_version:"11.0.0", test_version2:"11.0.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
