###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_dos_vuln_feb14_win.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Mozilla Firefox Cookie Verification Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804501");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-6167");
  script_bugtraq_id(62969);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-19 11:18:41 +0530 (Wed, 19 Feb 2014)");
  script_name("Mozilla Firefox Cookie Verification Denial of Service Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to improper handling of the browser.cookie cookie header.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to terminate a user's session on
a website, which will not allow the attacker to log back in to the website
until after the browser has been restarted.");
  script_tag(name:"affected", value:"Mozilla Firefox version 19.0 on Windows");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/121");
  script_xref(name:"URL", value:"http://redmine.lighttpd.net/issues/2188");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=858215");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ffVer, test_version:"19.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
