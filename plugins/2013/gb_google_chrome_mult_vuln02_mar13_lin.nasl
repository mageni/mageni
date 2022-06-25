###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_mar13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-02 March 2013 (Linux)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803433");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0902", "CVE-2013-0903", "CVE-2013-0904", "CVE-2013-0905",
                "CVE-2013-0906", "CVE-2013-0907", "CVE-2013-0908", "CVE-2013-0909",
                "CVE-2013-0910", "CVE-2013-0911");
  script_bugtraq_id(58291);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 13:55:17 +0530 (Mon, 11 Mar 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 March 2013 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/52454");
  script_xref(name:"URL", value:"https://chromiumcodereview.appspot.com/12212091");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_4.html");

  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  with higher privileges, corrupt memory, processing of databases outside
  a restricted origin path.");

  script_tag(name:"affected", value:"Google Chrome versions prior to 25.0.1364.152 on Linux");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - Use-after-free error exist in Frame loader, Browser navigation handling,
    SVG animations.

  - Unknown error exist in Web Audio, Indexed DB, Handling of bindings for
    extension processes, Loading browser plug-in.

  - Race condition error exists in media thread handling.

  - Path traversal error exists when handling database.

  - Origin identifier is not properly sanitized during database handling.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 25.0.1364.152 or later.");

  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"25.0.1364.152")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
