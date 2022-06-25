###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_http_header_sec_bypass_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apple Mac OS X Web Service component (HTTP header) Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806127");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-7031");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:05:48 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Web Service component (HTTP header) Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an  error in Web
  Service component it omits an unspecified HTTP header configuration.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to  bypass intended access restrictions via unknown vectors.");

  script_tag(name:"affected", value:"Apple Mac OS X Server versions before 5.0.15");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Server version
  5.0.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205376");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Oct/msg00009.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"5.0.15"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"5.0.15");
  security_message(data:report);
  exit(0);
}
exit(0);
