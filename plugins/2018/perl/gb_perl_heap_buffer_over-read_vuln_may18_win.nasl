###############################################################################
# OpenVAS Vulnerability Test
#
# Perl Heap-Based Buffer Over-read Vulnerability May18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:perl:perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812888");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-6798");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-18 17:20:41 +0530 (Fri, 18 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Perl Heap-Based Buffer Over-read Vulnerability May18 (Windows)");

  script_tag(name:"summary", value:"This host is running Perl and is
  prone to heap-based buffer over-read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Perl unable to
  sanitize against a crafted locale dependent regular expression.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a heap-based buffer over-read and potentially information disclosure.");

  script_tag(name:"affected", value:"Perl versions 5.22 through 5.26
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Perl version 5.26.2 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://rt.perl.org/Public/Bug/Display.html?id=131844");
  script_xref(name:"URL", value:"https://www.perl.org/get.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pver = infos['version'];
ppath = infos['location'];

if(version_in_range( version:pver, test_version:"5.22", test_version2:"5.26" ))
{
  report = report_fixed_ver(installed_version:pver, fixed_version:"5.26.2", install_path:ppath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
