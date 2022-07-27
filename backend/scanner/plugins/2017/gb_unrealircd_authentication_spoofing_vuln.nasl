###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unrealircd_authentication_spoofing_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# UnrealIRCd Authentication Spoofing Vulnerability
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

CPE = "cpe:/a:unrealircd:unrealircd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809883");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-7144");
  script_bugtraq_id(92763);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 16:51:06 +0530 (Fri, 03 Feb 2017)");
  script_name("UnrealIRCd Authentication Spoofing Vulnerability");

  script_tag(name:"summary", value:"This host is installed with UnrealIRCd
  and is prone to authentication spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  the 'm_authenticate' function in 'modules/m_sasl.c' script.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allows remote attackers to spoof certificate fingerprints and consequently
  log in as another user.");

  script_tag(name:"affected", value:"UnrealIRCd before 3.2.10.7 and
  4.x before 4.0.6.");

  script_tag(name:"solution", value:"Upgrade to UnrealIRCd 3.2.10.7,
  or 4.0.6, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/420");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/05/8");
  script_xref(name:"URL", value:"https://github.com/unrealircd/unrealircd/commit/f473e355e1dc422c4f019dbf86bc50ba1a34a766");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_unrealircd_detect.nasl");
  script_mandatory_keys("UnrealIRCD/Detected");
  script_xref(name:"URL", value:"https://bugs.unrealircd.org/main_page.php");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!UnPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!UnVer = get_app_version(cpe:CPE, port:UnPort)){
  exit(0);
}

## Reminder: UnrealIRCd 3.2.x End Of Life
if(version_is_less(version:UnVer, test_version:"3.2.10.7"))
{
  fix = "3.2.10.7";
  VULN = TRUE;
}

else if(UnVer =~ "^4\.")
{
  if(version_in_range(version:UnVer, test_version:"4.0", test_version2:"4.0.5"))
  {
    fix = "4.0.6";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:UnVer, fixed_version:fix);
  security_message(data:report, port:UnPort);
  exit(0);
}

exit(0);
