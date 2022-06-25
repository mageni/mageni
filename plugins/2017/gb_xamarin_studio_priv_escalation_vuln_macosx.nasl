##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xamarin_studio_priv_escalation_vuln_macosx.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Xamarin Studio Privilege Escalation Vulnerability - Mac OS X
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:xamarin:studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811708");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-8665");
  script_bugtraq_id(100308);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-17 16:37:16 +0530 (Thu, 17 Aug 2017)");
  script_name("Xamarin Studio Privilege Escalation Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Xamarin Studio
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'Xamarin.iOS' update component of the application which improperly handles
  directories and binaries.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to escalate privileges and run arbitrary code as root. An attacker
  could then install programs, or view, change, or delete data or create new
  accounts that have full user rights.");

  script_tag(name:"affected", value:"Xamarin Studio for Mac version 6.2.1
  (build 3) and version 6.3 (build 863).");

  script_tag(name:"solution", value:"Upgrade to latest version of Visual Studio
  for Mac which has replaced Xamarin Studio.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4037359");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20170403");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xamarin_studio_detect_macosx.nasl");
  script_mandatory_keys("Xamarin/Studio/MacOSX/Version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/mac/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!xarVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(xarVer == "6.2.1.3" || xarVer == "6.3.863")
{
  report = report_fixed_ver(installed_version:xarVer, fixed_version:"Latest Visual Studio for Mac");
  security_message(data:report);
  exit(0);
}
exit(0);
