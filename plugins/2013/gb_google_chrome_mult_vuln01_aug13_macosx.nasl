###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_aug13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 August13 (Mac OS X)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803879");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902",
                "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_bugtraq_id(61885, 61887, 61891, 61886, 61888, 61889, 61890);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-26 13:05:48 +0530 (Mon, 26 Aug 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 August13 (Mac OS X)");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 29.0.1547.57 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Some unspecified errors exist.

  - An error exists when handling file paths.

  - An integer overflow error exists within ANGLE.

  - Insecure permissions when creating certain shared memory files.

  - Use-after-free error exists within XSLT, media element and document parsing.");
  script_tag(name:"affected", value:"Google Chrome version prior to 29.0.1547.57 on Mac OS X.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially sensitive information, compromise a user's system and other attacks may also be possible.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54479");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/08/stable-channel-update.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"29.0.1547.57"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
