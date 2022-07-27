###############################################################################
# OpenVAS Vulnerability Test
#
# Apple QuickTime Multiple Vulnerabilities - Jun09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800578");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0951", "CVE-2009-0952", "CVE-2009-0953",
                "CVE-2009-0954", "CVE-2009-0955", "CVE-2009-0956",
                "CVE-2009-0957", "CVE-2009-0185", "CVE-2009-0188");
  script_bugtraq_id(35161, 35168, 35164, 35167, 35166, 35162, 35165, 35163, 35159);
  script_name("Apple QuickTime Multiple Vulnerabilities - Jun09");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"affected", value:"Apple QuickTime version prior to 7.6.2 on Windows.");
  script_tag(name:"insight", value:"The flaws are due to

  - an unspecified error while handling malicious 1)FLC compression files,
    2)compressed PSD images, 3)PICT images, 4)JP2 images.

  - an error in the parsing of Sorenson Video 3 content.

  - a boundary error in the processing of MS ADPCM encoded audio data.

  - an error due to the usage of uninitialised memory when a movie with a
    user data atom size of zero is viewed.

  - a sign extension error while the handling malicious image description
    atoms in an Apple video file.");
  script_tag(name:"summary", value:"The host is installed with Apple QuickTime which is prone to
  Multiple Vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.2 or later.");
  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code,
  cause memory corruption or unexpected application termination via specially
  crafted files, images and videos.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35091");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00000.html");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

quicktimeVer = get_kb_item("QuickTime/Win/Ver");
if(!quicktimeVer)
  exit(0);

if(version_is_less(version:quicktimeVer, test_version:"7.6.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
