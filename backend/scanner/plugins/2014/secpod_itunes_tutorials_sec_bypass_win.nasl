###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_tutorials_sec_bypass_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Apple iTunes Tutorials Window Security Bypass Vulnerability (Windows)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804232");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1242");
  script_bugtraq_id(65088);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-30 16:54:49 +0530 (Thu, 30 Jan 2014)");
  script_name("Apple iTunes Tutorials Window Security Bypass Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Apple iTunes and is prone to security bypass
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to iTunes Tutorials window, which uses a non-secure HTTP
connection to retrieve content.");
  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to perform man-in-the-middle
attacks and obtain sensitive information..");
  script_tag(name:"affected", value:"Apple iTunes before 11.1.4 on Windows");
  script_tag(name:"solution", value:"Upgrade to version 11.1.4 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90653");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ituneVer = get_app_version(cpe:CPE)){
    exit(0);
}

if(version_is_less(version:ituneVer, test_version:"11.1.4"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
