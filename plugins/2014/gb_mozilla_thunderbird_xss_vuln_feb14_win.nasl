###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_xss_vuln_feb14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Mozilla Thunderbird Multiple XSS Vulnerabilities Feb14 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804503");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-6674", "CVE-2014-2018");
  script_bugtraq_id(65158, 65620);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-19 15:59:44 +0530 (Wed, 19 Feb 2014)");
  script_name("Mozilla Thunderbird Multiple XSS Vulnerabilities Feb14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird and is prone to multiple cross
site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to the program does not validate input related to data URLs in
IFRAME elements or EMBED or OBJECT element before returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary script code
in a user's browser session within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version 17.x through 17.0.8 on Windows");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 23.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/863369");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31223");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/thunderbird");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:tbVer, test_version:"17.0", test_version2:"17.0.8"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
