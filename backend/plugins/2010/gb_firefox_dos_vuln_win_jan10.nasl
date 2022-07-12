###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_dos_vuln_win_jan10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Firefox 'nsObserverList::FillObserverArray' DOS Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800416");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0220");
  script_name("Firefox 'nsObserverList::FillObserverArray' DOS Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://isc.sans.org/diary.html?storyid=7897");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=507114");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/3.5.7/releasenotes");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful remote exploitation will allow attackers to  crash application
  via a crafted web site that triggers memory consumption and an accompanying
  Low Memory alert dialog, and also triggers attempted removal of an observer from an empty observers array.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.5.7 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'nsObserverList::FillObserverArray()' function
  in 'xpcom/ds/nsObserverList.cpp'");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.7");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone to
  Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(!firefoxVer){
  exit(0);
}

if(version_is_less(version:firefoxVer, test_version:"3.5.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
