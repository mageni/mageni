###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_security_bypass_vuln.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Firefox Security Bypass Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801637");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2009-5017");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mozilla Firefox Security Bypass Vulnerability (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=511859");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=522634");
  script_xref(name:"URL", value:"http://sirdarckcat.blogspot.com/2009/10/couple-of-unicode-issues-on-php-and.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass cross-site scripting
  protection mechanisms via a crafted string.");
  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 3.6 Beta 3.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of overlong UTF-8 encoding,
  which makes it easier for remote attackers to bypass cross-site scripting
  protection mechanisms via a crafted string.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6 Beta 3 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox and is prone to security
  bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/upgrade.html");
  exit(0);
}


include("version_func.inc");

fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

if(version_in_range(version:fpVer, test_version:"3.6.b1", test_version2:"3.6.b2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
