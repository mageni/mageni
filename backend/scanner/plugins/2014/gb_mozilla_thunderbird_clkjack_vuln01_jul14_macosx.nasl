###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_clkjack_vuln01_jul14_macosx.nasl 38580 2014-07-04 10:38:51Z jul$
#
# Mozilla Thunderbird clickjacking Vulnerability-01 July14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804708");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-1539");
  script_bugtraq_id(67967);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-04 10:41:41 +0530 (Fri, 04 Jul 2014)");
  script_name("Mozilla Thunderbird clickjacking Vulnerability-01 July14 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to error in handling cursor rendering related to an embedded
flash object.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct clickjacking attacks
and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version 24.x through 24.6 on Mac OS X");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59171");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(tbVer =~ "^24\." && version_in_range(version:tbVer,
                       test_version:"24.0", test_version2:"24.6"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
