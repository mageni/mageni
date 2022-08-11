###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mult_vuln01_feb13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities -01 Feb13 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803425");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0784", "CVE-2013-0783", "CVE-2013-0782", "CVE-2013-0781",
                "CVE-2013-0780", "CVE-2013-0779", "CVE-2013-0778", "CVE-2013-0777",
                "CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774",
                "CVE-2013-0775", "CVE-2013-0776");
  script_bugtraq_id(58040, 58037, 58047, 58049, 58043, 58051, 58050, 58048, 58036,
                    58034, 58041, 58038, 58042, 58044);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-21 19:36:53 +0530 (Thu, 21 Feb 2013)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities -01 Feb13 (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52249");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52280");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=827070");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/cve/CVE-2013-0784");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 17.0.3 on Mac OS X");

  script_tag(name:"insight", value:"- Error when handling a WebIDL object

  - Error in displaying the content of a 407 response of a proxy

  - Unspecified errors in 'nsSaveAsCharset::DoCharsetConversion()' function,
    Chrome Object Wrappers (COW) and in System Only Wrappers (SOW).

  - Use-after-free error in the below functions

    'nsDisplayBoxShadowOuter::Paint()'

    'nsPrintEngine::CommonPrint()'

    'nsOverflowContinuationTracker::Finish()'

    'nsImageLoadingContent::OnStopContainer()'

  - Out-of-bound read error in below functions

    'ClusterIterator::NextCluster()'

    'nsCodingStateMachine::NextState()'

    'mozilla::image::RasterImage::DrawFrameTo()', when rendering GIF images.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 17.0.3 or later.");
  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities.");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/thunderbird");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("ThunderBird/MacOSX/Version");

if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"17.0.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
