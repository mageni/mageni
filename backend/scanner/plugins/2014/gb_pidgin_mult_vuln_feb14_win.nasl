###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_vuln_feb14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Pidgin Multiple Vulnerabilities Feb 2014 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804314");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479",
                "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484",
                "CVE-2013-6485", "CVE-2013-6486", "CVE-2013-6487", "CVE-2013-6489",
                "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65492, 65243, 65189, 65188, 65192, 65195);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-14 16:39:04 +0530 (Fri, 14 Feb 2014)");
  script_name("Pidgin Multiple Vulnerabilities Feb 2014 (Windows)");


  script_tag(name:"summary", value:"The host is installed with Pidgin and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to an,

  - Improper validation of data by the Yahoo protocol plugin.

  - Improper validation of argument counts by IRC protocol plugin.

  - Improper validation of input to content-length header.

  - Integer signedness error in the 'MXit' functionality.

  - Integer overflow in 'ibpurple/protocols/gg/lib/http.c' in the 'Gadu-Gadu'
(gg) parser.

  - Error due to incomplete fix for earlier flaw.

  - Integer overflow condition in the 'process_chunked_data' function in 'util.c'.

  - Error in 'STUN' protocol implementation in 'libpurple'.

  - Error in the 'XMPP' protocol plugin in 'libpurple'.

  - Error in the MSN module.

  - Improper validation of the length field in 'libpurple/protocols/yahoo/libymsg.c'.

  - Improper allocation of memory by 'util.c' in 'libpurple'.

  - Error in the libx11 library.

  - Multiple integer signedness errors in libpurple.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service or execute arbitrary programs or spoof iq traffic.");
  script_tag(name:"affected", value:"Pidgin version before 2.10.8.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.8 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56693/");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=70");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=85");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!pidVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:pidVer, test_version:"2.10.8"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
