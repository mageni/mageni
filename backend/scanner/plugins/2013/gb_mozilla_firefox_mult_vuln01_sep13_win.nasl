###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_sep13_win.nasl 31965 2013-09-24 11:59:47Z sep$
#
# Mozilla Firefox Multiple Vulnerabilities-01 Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804005");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1721",
                "CVE-2013-1722", "CVE-2013-1723", "CVE-2013-1724", "CVE-2013-1725",
                "CVE-2013-1726", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732",
                "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_bugtraq_id(62463, 62462, 62465, 62470, 62460, 62472, 62464, 62467,
                    62482, 62468, 62473, 62469, 62479, 62478, 62475, 62466);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:59:47 +0530 (Tue, 24 Sep 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Sep13 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 24.0 or later.");
  script_tag(name:"insight", value:"For more details about the vulnerabilities, refer the reference section.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 24.0 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain escalated privileges,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54892");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"24.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
