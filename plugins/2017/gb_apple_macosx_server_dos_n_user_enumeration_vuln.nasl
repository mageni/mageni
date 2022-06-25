###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_server_dos_n_user_enumeration_vuln.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple OS X Server Denial of Service And User Enumeration Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810599");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2016-0751", "CVE-2007-6750", "CVE-2017-2382");
  script_bugtraq_id(90690, 90689);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-03 10:32:56 +0530 (Mon, 03 Apr 2017)");
  script_name("Apple OS X Server Denial of Service And User Enumeration Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Apple OS X Server
  and is prone to denial of service and user enumeration vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An insufficient permission check for access in Wiki server.

  - The partial HTTP requests in Web Server.

  - The caching for unknown MIME types, which can cause a global cache to grow
    indefinitely.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to enumerate users and cause a denial of service condition.");

  script_tag(name:"affected", value:"Apple OS X Server before 5.3");

  script_tag(name:"solution", value:"Upgrade to Apple OS X Server 5.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207604");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version", "ssh/login/osx_version");
  script_xref(name:"URL", value:"http://www.apple.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.12.4")){
  exit(0);
}

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"5.3"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"5.3");
  security_message(data:report);
  exit(0);
}

exit(99);