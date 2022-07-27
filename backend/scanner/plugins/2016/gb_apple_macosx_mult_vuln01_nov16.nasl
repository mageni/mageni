###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_nov16.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-01 November-2016
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
  script_oid("1.3.6.1.4.1.25623.1.0.810209");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2016-1792", "CVE-2016-1791", "CVE-2016-1793", "CVE-2016-1794",
                "CVE-2016-1795", "CVE-2016-1796", "CVE-2016-1797", "CVE-2016-1798",
                "CVE-2016-1799", "CVE-2016-1800", "CVE-2016-1801", "CVE-2016-1802",
                "CVE-2016-1803", "CVE-2016-1805", "CVE-2016-1806", "CVE-2016-1807",
                "CVE-2016-1808", "CVE-2016-1809", "CVE-2016-1810", "CVE-2016-1811",
                "CVE-2016-1812", "CVE-2016-1860", "CVE-2016-1862", "CVE-2016-1814",
                "CVE-2016-1815", "CVE-2016-1817", "CVE-2016-1818", "CVE-2016-1819",
                "CVE-2016-1853", "CVE-2016-1851", "CVE-2016-1850", "CVE-2016-1848",
                "CVE-2016-1847", "CVE-2016-1861", "CVE-2016-1846", "CVE-2016-1804",
                "CVE-2016-1843", "CVE-2016-1844", "CVE-2016-1842", "CVE-2016-1841",
                "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836",
                "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840",
                "CVE-2016-1832", "CVE-2016-1826", "CVE-2016-1827", "CVE-2016-1828",
                "CVE-2016-1829", "CVE-2016-1830", "CVE-2016-1831", "CVE-2016-1825",
                "CVE-2016-1823", "CVE-2016-1824", "CVE-2016-1822", "CVE-2016-1821",
                "CVE-2016-1820", "CVE-2016-1816", "CVE-2016-1813", "CVE-2015-8865",
                "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-4070", "CVE-2016-4071",
                "CVE-2016-4072", "CVE-2016-4073");
  script_bugtraq_id(90696, 90694);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 November-2016");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x before
  10.11.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");
  script_xref(name:"URL", value:"https://www.apple.com");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11.5");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);