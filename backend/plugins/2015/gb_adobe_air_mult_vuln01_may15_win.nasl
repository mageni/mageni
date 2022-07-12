###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_may15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Air Multiple Vulnerabilities - 01 May15 (Windows)
#
# Authors:
# Rinu <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805620");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3077", "CVE-2015-3078", "CVE-2015-3079", "CVE-2015-3080",
                "CVE-2015-3081", "CVE-2015-3082", "CVE-2015-3083", "CVE-2015-3084",
                "CVE-2015-3085", "CVE-2015-3086", "CVE-2015-3087", "CVE-2015-3088",
                "CVE-2015-3089", "CVE-2015-3090", "CVE-2015-3091", "CVE-2015-3092",
                "CVE-2015-3093");
  script_bugtraq_id(74614, 74605, 74612, 74608, 74613, 74610, 74616, 74609, 74617);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-15 10:48:48 +0530 (Fri, 15 May 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Air Multiple Vulnerabilities - 01 May15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Air and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Improper validation of user supplied input.

  - A flaw in the Broker that is due to the BrokerCreateFile method not properly
    sanitizing user input.

  - An integer overflow condition that is triggered as user-supplied input is
    not properly validated.

  - An overflow condition that is triggered as user-supplied input is not
    properly validated.

  - Multiple unspecified memory disclosure flaws in Adobe Flash Player.

  - Multiple unspecified type confusion flaws in Adobe Flash Player.

  - Multiple unspecified flaws in Adobe Flash Player.

  - A a use-after-free error Adobe Flash Player.

  - An unspecified TOCTOU flaw in Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially execute arbitrary
  code, bypass security restrictions and gain access to sensitive information,
  bypass protected mode, bypass validation mechanisms and write arbitrary data,
  bypass the sandbox when chained with another vulnerability, bypass ASLR
  protection mechanisms.");

  script_tag(name:"affected", value:"Adobe Air versions before 17.0.0.172 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version 17.0.0.172
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!airVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:airVer, test_version:"17.0.0.172"))
{
  report = 'Installed version: ' + airVer + '\n' +
           'Fixed version:     ' + "17.0.0.172" + '\n';
  security_message(data:report);
  exit(0);
}
