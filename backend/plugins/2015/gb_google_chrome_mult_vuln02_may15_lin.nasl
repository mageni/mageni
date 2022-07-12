###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_may15_lin.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - 02 - May15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805633");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254",
                "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258",
                "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1263",
                "CVE-2015-1264", "CVE-2015-1265", "CVE-2015-3910");
  script_bugtraq_id(74723);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-27 09:42:43 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Multiple Vulnerabilities - 02 - May15 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple unspecified vulnerabilities in Google V8.

  - Use-after-free vulnerability in the SpeechRecognitionClient implementation
  in the Speech subsystem.

  - common/partial_circular_buffer.cc script in Google Chrome does not properly
  handle wraps.

  - Vulnerability in core/html/parser/HTMLConstructionSite.cpp in the DOM
  implementation in Blink, as used in Google Chrome.

  - Vulnerability in core/dom/Document.cpp in Blink, as used in Google Chrome
  which allows the inheritance of the designMode attribute.

  - Use-after-free vulnerability in
  content/renderer/media/webaudio_capturer_source.cc  script in the WebAudio
  implementation.

  - Use-after-free vulnerability in the SVG implementation in Blink.

  - platform/graphics/filters/FEColorMatrix.cpp script in the SVG implementation
  in Blink.

  - Google Chrome relies on libvpx code that was not built with an appropriate
  size-limit value.

  - PDFium, as used in Google Chrome, does not properly initialize memory.

  - Multiple use-after-free vulnerabilities in
  content/renderer/media/user_media_client_impl.cc script in the WebRTC
  implementation.

  - Cross-site scripting (XSS) vulnerability in Google Chrome.

  - The Spellcheck API implementation in Google Chrome before does not use an
  HTTPS session for downloading a Hunspell dictionary.

  - platform/fonts/shaping/HarfBuzzShaper.cpp script in Blink, does not
  initialize a certain width field.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service, inject arbitrary web script, spoof the
  URL bar or deliver misleading popup content, bypass the Same Origin Policy and
  a sandbox protection mechanism, execute arbitrary code and allow
  man-in-the-middle attackers to deliver incorrect spelling suggestions or
  possibly have unspecified other impact via crafted dimensions.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  43.0.2357.65 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  43.0.2357.65 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/05/stable-channel-update_19.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"43.0.2357.65"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     43.0.2357.65'  + '\n';
  security_message(data:report);
  exit(0);
}
