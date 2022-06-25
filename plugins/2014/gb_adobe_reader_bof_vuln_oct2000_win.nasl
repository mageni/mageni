###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader '/Registry' and '/Ordering' Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804622");
  script_version("2019-04-26T10:52:18+0000");
  script_cve_id("CVE-2000-0713");
  script_bugtraq_id(1509);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-26 10:52:18 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2014-06-04 14:12:30 +0530 (Wed, 04 Jun 2014)");
  script_name("Adobe Reader '/Registry' and '/Ordering' Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_old_adobe_reader_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader-Old/Ver");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/31554");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/5002");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2000-07/0382.html");
  script_xref(name:"URL", value:"ftp://ftp.adobe.com/pub/adobe/acrobat/win/4.x/ac405up2.exe");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the program fails to validate the '/Registry' and '/Ordering'
  strings");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader version 4.0.5 and before on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor link.");

  script_tag(name:"qod", value:"50"); # Detection-VT is not capable to gather if the patch was applied and there is no registry_unreliable QoD
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:readerVer, test_version:"4.0.5")) {
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"See references");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);