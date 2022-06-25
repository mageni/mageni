###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_privilege_escalation_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Adobe Shockwave Player Privilege Escalation Vulnerability
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

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810816");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-2983");
  script_bugtraq_id(96863);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 11:52:16 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Shockwave Player Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave
  Player and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure library
  loading (DLL hijacking) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to elevate privileges.");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before
  12.2.8.198 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version
  12.2.8.198 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb17-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"12.2.8.198"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"12.2.8.198");
  security_message(data:report);
  exit(0);
}
