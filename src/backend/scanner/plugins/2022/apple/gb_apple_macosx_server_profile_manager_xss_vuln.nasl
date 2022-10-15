# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826557");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2020-9995");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-07 20:25:00 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2022-09-28 09:52:31 +0530 (Wed, 28 Sep 2022)");
  script_name("Apple OS X Server Profile Manager Cross Site Scripting Vulnerability (HT211932)");

  script_tag(name:"summary", value:"Apple OS X Server is prone to an open redirect
  or cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an issue existed in the
  parsing of URLs in Profile Manager.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct open redirect or cross site scripting attack.");

  script_tag(name:"affected", value:"Apple OS X Server before 5.11");

  script_tag(name:"solution", value:"Upgrade to Apple OS X Server 5.11 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211932");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"5.11"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"5.11");
  security_message(data:report);
  exit(0);
}
exit(0);
