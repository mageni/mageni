###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Internet Security Multiple Vulnerabilities May18 (Windows)
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:trendmicro:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813335");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6232", "CVE-2018-6233", "CVE-2018-6234", "CVE-2018-6235",
                "CVE-2018-6236", "CVE-2018-3608", "CVE-2018-10513", "CVE-2018-10514",
                "CVE-2018-15363");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-08 13:30:09 +0530 (Tue, 08 May 2018)");
  ## Patched version is not available from registry or anywhere, so it can result in FP for 12.0 patched versions
  script_tag(name:"qod", value:"30");
  script_name("Trend Micro Internet Security Multiple Vulnerabilities May18 (Windows)");

  script_tag(name:"summary", value:"This host is running Trend Micro Internet Security
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple buffer overflow errors.

  - An out-of-bounds Read error.

  - An out-of-bounds write error.

  - An unknown error exist with Time-Of-Check/Time-Of-Use.

  - User-Mode Hooking (UMH) driver allowing to create a specially crafted packet.

  - Processing of request ID 0x2002 for IDAMSPMASTER in the service process
    coreServiceShell.exe");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, disclose sensitive information and inject malicious
  code into other processes.");

  script_tag(name:"affected", value:"Trend Micro Internet Security 12.0 (ignore if
  patch is applied or has the latest updated version 12.0.1226) and below on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Trend Micro Internet Security 12.0.1226
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://esupport.trendmicro.com/en-us/home/pages/technical-support/1119591.aspx");
  script_xref(name:"URL", value:"https://esupport.trendmicro.com/en-US/home/pages/technical-support/1120237.aspx");
  script_xref(name:"URL", value:"https://esupport.trendmicro.com/en-US/home/pages/technical-support/1120742.aspx");
  script_xref(name:"URL", value:"https://esupport.trendmicro.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trendmicro_internet_security_detect.nasl");
  script_mandatory_keys("TrendMicro/IS/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
tVer = infos['version'];
tPath = infos['location'];

if(version_is_less_equal(version:tVer, test_version:"12.0"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"Latest update 12.0.1226", install_path:tPath);
  security_message(data:report);
  exit(0);
}
exit(0);
