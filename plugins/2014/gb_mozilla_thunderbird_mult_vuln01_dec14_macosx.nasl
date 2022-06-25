###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mult_vuln01_dec14_macosx.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities-01 Dec14 (Mac OS X)
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805222");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-1594", "CVE-2014-1593", "CVE-2014-1592", "CVE-2014-1590",
                "CVE-2014-1587", "CVE-2014-1595");
  script_bugtraq_id(71396, 71395, 71398, 71397, 71391, 71394);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-16 11:16:58 +0530 (Tue, 16 Dec 2014)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 Dec14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A bad cast issue from the BasicThebesLayer to BasicContainerLayer.

  - An error when parsing media content within the 'mozilla::FileBlockCache::Read'
  function.

  - A use-after-free error when parsing certain HTML within the
  'nsHtml5TreeOperation' class.

  - An error that is triggered when handling JavaScript objects that are passed
  to XMLHttpRequest that mimics an input stream.

  - Multiple unspecified errors.

  - - The CoreGraphics framework logging potentially sensitive input data
  to the /tmp directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  disclose potentially sensitive information, compromise a user's system and
  have other unknown impacts.");

  script_tag(name:"affected", value:"Mozilla Thunderbird before version 31.3
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  31.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60558");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-89");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-88");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"31.3"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
