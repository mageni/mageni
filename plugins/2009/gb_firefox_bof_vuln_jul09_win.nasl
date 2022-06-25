###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_bof_vuln_jul09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox Buffer Overflow Vulnerability - July09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800846");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2478", "CVE-2009-2479");
  script_bugtraq_id(35707);
  script_name("Mozilla Firefox Buffer Overflow Vulnerability - July09 (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9158");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51729");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=503286");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful attacks will let attackers to can cause Denial of Service to the
  legitimate user.");
  script_tag(name:"affected", value:"Firefox version 3.5.1 and prior on Windows");
  script_tag(name:"insight", value:"- A NULL pointer dereference error exists due an unspecified vectors, related
    to a 'flash bug.' which can cause application crash.

  - Stack-based buffer overflow error is caused by sending an overly long string
    argument to the 'document.write' method.");
  script_tag(name:"solution", value:"Upgrade to  Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to Buffer Overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/upgrade.html");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less_equal(version:ffVer, test_version:"3.5.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
