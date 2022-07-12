###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_dos_nd_access_bypass_vuln.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Denial of Service And Access Bypass Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810223");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2014-1296", "CVE-2013-4164");
  script_bugtraq_id(67024, 63873);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-17 22:43:28 -0800 (Thu, 17 Nov 2016)");
  script_name("Apple Mac OS X Denial of Service And Access Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to denial of service and access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to the CFNetwork does
  not ensure that a Set-Cookie HTTP header is complete before interpreting the
  header's value and a heap-based buffer overflow error in Ruby.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption) and
  to bypass access restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.7.x through
  10.7.5");

  script_tag(name:"solution", value:"These vulnerabilities were addressed in Security Update 2014-002.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod", value:"30"); ## build information not available

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT201541");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT202966");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.7");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.7")
{
  if(version_in_range(version:osVer, test_version:"10.7.0", test_version2:"10.7.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"See Vendor");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);