###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_xss_utf-8_vuln_win.nasl 31795 2013-10-01 09:55:08Z sep$
#
# Opera Cross-Site Scripting (XSS) Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:opera:opera_browser";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804102");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4705");
  script_bugtraq_id(31795);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-01 09:52:30 +0530 (Tue, 01 Oct 2013)");
  script_name("Opera Cross-Site Scripting (XSS) Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Opera and is prone to XSS attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Opera version 15.00 or later.");
  script_tag(name:"insight", value:"The flaw is due to some error when encoding settings are set to UTF-8.");
  script_tag(name:"affected", value:"Opera versions prior to 15.00 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute an arbitrary web
script or HTML on the user's web browser.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN01094166/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/jvndb/JVNDB-2013-000086");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1500");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!operaVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"15.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
