###############################################################################
# OpenVAS Vulnerability Test
#
# Firefox Web Browser FTP Client XSS Vulnerability (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800043");
  script_version("2019-04-26T10:13:49+0000");
  script_tag(name:"last_modification", value:"2019-04-26 10:13:49 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-4723");
  script_bugtraq_id(31855);
  script_name("Firefox Web Browser FTP Client XSS Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31855/exploit");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all-older.html");

  script_tag(name:"impact", value:"Successful remote attack result in injection of arbitrary web
  script or HTML code.");

  script_tag(name:"affected", value:"Firefox version 3.0.1 to 3.0.3 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to the way browser handles web script or html via
  ftp:// URL for an html document within a JPG, PDF, or TXT files.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to Cross Site Scripting (XSS) Vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_in_range(version:ffVer, test_version:"3.0.1", test_version2:"3.0.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);