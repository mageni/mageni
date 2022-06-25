###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_insecure_lib_load_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# TeamViewer File Opening Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801436");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2010-3128");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("TeamViewer File Opening Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41112");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14734/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2174");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
  libraries from the current working directory.");
  script_tag(name:"solution", value:"Update to version 5.0.9104 or later.");
  script_tag(name:"summary", value:"This host is installed with TeamViewer and is prone to insecure
  library loading vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code and conduct DLL hijacking attacks via a Trojan horse dwmapi.dll that is
  located in the same folder as a .tvs or .tvc file.");
  script_tag(name:"affected", value:"TeamViewer version 5.0.8703 and prior");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.teamviewer.com/index.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)) {
  exit(0);
}

if(version_is_less(version:Ver, test_version:"5.0.9104"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"5.0.9104");
  security_message(port:0, data:report);
  exit(0);
}
