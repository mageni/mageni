###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_mar16.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-01 March-2016
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806693");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2015-7551", "CVE-2016-1733", "CVE-2016-1732", "CVE-2016-1734",
                "CVE-2016-1735", "CVE-2016-1736", "CVE-2016-1737", "CVE-2016-1740",
                "CVE-2016-1738", "CVE-2016-1741", "CVE-2016-1743", "CVE-2016-1744",
                "CVE-2016-1745", "CVE-2016-1746", "CVE-2016-1747", "CVE-2016-1748",
                "CVE-2016-1749", "CVE-2016-1752", "CVE-2016-1753", "CVE-2016-1754",
                "CVE-2016-1755", "CVE-2016-1756", "CVE-2016-1757", "CVE-2016-1758",
                "CVE-2016-1759", "CVE-2016-1761", "CVE-2016-1764", "CVE-2016-1765",
                "CVE-2016-1767", "CVE-2016-1768", "CVE-2016-1769", "CVE-2016-1770",
                "CVE-2016-1773", "CVE-2016-1775", "CVE-2016-1750", "CVE-2016-1788",
                "CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8659", "CVE-2015-1819",
                "CVE-2015-5312", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7942",
                "CVE-2015-8035", "CVE-2015-8242", "CVE-2016-1762", "CVE-2016-0777",
                "CVE-2016-0778", "CVE-2015-3195", "CVE-2014-9495", "CVE-2015-0973",
                "CVE-2016-1950", "CVE-2016-0801", "CVE-2016-0802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:28 +0530 (Fri, 01 Apr 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 March-2016");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, trigger a dialing action,
  bypass a code-signing protection mechanism.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x before
  10.11.4, 10.9.x through 10.9.5, 10.10.x through 10.10.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11.4 or later, or apply aptch from vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206167");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|1[01])");
  script_xref(name:"URL", value:"https://www.apple.com");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|1[01])"){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4")||
   version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if((osVer == "10.10.5") || (osVer == "10.9.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1713"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
  else if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1712"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

else if(osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.4")){
    fix = "10.11.4";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);