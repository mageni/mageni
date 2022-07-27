###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_livecycle_designer_untrusted_search_path_vuln_win.nasl 11357 2018-09-12 10:57:05Z asteins $
#
# Adobe LiveCycle Designer Untrusted Search Path Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802960");
  script_version("$Revision: 11357 $");
  script_cve_id("CVE-2010-5212");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:57:05 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-11 19:03:45 +0530 (Tue, 11 Sep 2012)");
  script_name("Adobe LiveCycle Designer Untrusted Search Path Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41417");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_livecycle_designer_detect_win.nasl");
  script_mandatory_keys("Adobe/LiveCycle/Designer");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code on the target system.");
  script_tag(name:"affected", value:"Adobe LiveCycle Designer version ES2 9.0.0.20091029.1.612548
on Windows");
  script_tag(name:"insight", value:"The flaw is due to the way it loads dynamic-link libraries.
The program uses a fixed path to look for specific files or libraries. This
path includes directories that may not be trusted or under user control. By
placing a custom version of the file or library in the path, the program will
load it before the legitimate version.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Adobe LiveCycle Designer and is
prone to untrusted search path vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

designVer = get_kb_item("Adobe/LiveCycle/Designer");
if(!designVer){
  exit(0);
}

## 9.0.0.20091029.1.612548 is the product version and 9000.2302.1.0 is the file version
if(version_is_equal(version:designVer, test_version:"9000.2302.1.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
