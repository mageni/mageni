###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_info_disc_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PuTTY Information Disclosure vulnerability (Windows)
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
CPE = "cpe:/a:putty:putty";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803880");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2011-4607");
  script_bugtraq_id(51021);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-26 15:35:39 +0530 (Mon, 26 Aug 2013)");
  script_name("PuTTY Information Disclosure vulnerability (Windows)");
  script_tag(name:"summary", value:"The host is installed with PuTTY and is prone to information disclosure
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 0.62 or later.");
  script_tag(name:"insight", value:"Flaw is due to improper handling of session passwords that were stored in the
memory during the keyboard-interactive authentication");
  script_tag(name:"affected", value:"PuTTY version 0.59 before 0.62 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to read the passwords within the memory in clear text until the program stops running.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2011/q4/500");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2011-4607");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/password-not-wiped.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/version");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

puttyVer = get_app_version(cpe:CPE);
if(!puttyVer){
  exit(0);
}

if(version_in_range(version:puttyVer, test_version:"0.59", test_version2:"0.61"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
