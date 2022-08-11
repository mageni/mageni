###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mfsa_2017-10_2017-12_macosx.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Mozilla Firefox ESR Security Updates(mfsa_2017-10_2017-12)-MAC OS X
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810758");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433",
                "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437",
                "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441",
                "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445",
                "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449",
                "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456",
                "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462",
                "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467",
                "CVE-2017-5469");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 11:47:46 +0530 (Thu, 20 Apr 2017)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2017-10_2017-12)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - An use-after-free in SMIL animation functions,

  - An use-after-free during transaction processing in the editor,

  - An out-of-bounds write with malicious font in Graphite 2,

  - An out-of-bounds write in Base64 encoding in NSS,

  - The buffer overflow in WebGL,

  - An origin confusion when reloading isolated data:text/html URL,

  - An use-after-free during focus handling,

  - An use-after-free in text input selection,

  - An use-after-free in frame selection,

  - An use-after-free in nsAutoPtr during XSLT processing,

  - An use-after-free in nsTArray Length() during XSLT processing,

  - An use-after-free in txExecutionState destructor during XSLT processing,

  - An use-after-free with selection during scroll events,

  - An use-after-free during style changes,

  - The memory corruption with accessibility and DOM manipulation,

  - An out-of-bounds write during BinHex decoding,

  - An buffer overflow while parsing application/http-index-format content,

  - An out-of-bounds read when HTTP/2 DATA frames are sent with incorrect dat

  - An out-of-bounds read during glyph processing,

  - An out-of-bounds read in ConvolvePixel,

  - An out-of-bounds write in ClearKeyDecryptor,

  - The vulnerabilities in Libevent library,

  - The sandbox escape allowing file system read access through file picker,

  - The sandbox escape through internal feed reader APIs,

  - The sandbox escape allowing local file system access,

  - The potential Buffer overflow in flex-generated code,

  - An uninitialized values used while parsing application/http-index-format

  - The crash during bidirectional unicode manipulation with animation,

  - An addressbar spoofing with onblur event,

  - An DRBG flaw in NSS and

  - The memory corruption when drawing Skia content");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, to delete arbitrary files by leveraging
  certain local file execution, to obtain sensitive information, and to cause
  a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  52.1 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 52.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-12/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"52.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.1");
  security_message(data:report);
  exit(0);
}
