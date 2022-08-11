###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_apr15_lin.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-02 Apr15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805468");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3335", "CVE-2015-3334", "CVE-2015-3333", "CVE-2015-1249",
                "CVE-2015-1247", "CVE-2015-1246", "CVE-2015-1244", "CVE-2015-1242",
                "CVE-2015-1241", "CVE-2015-1240", "CVE-2015-1238", "CVE-2015-1237",
                "CVE-2015-1236", "CVE-2015-1235", "CVE-2015-3336");
  script_bugtraq_id(72715, 74227, 74225, 74221);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-21 18:46:52 +0530 (Tue, 21 Apr 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Apr15 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Missing address space usage limitation in the NaCl process.

  - Permissions for camera and microphone are merged into a single 'Media'
  permission instead of treated as two separate permission.

  - Flaw in the 'SearchEngineTabHelper::OnPageHasOSDD' function in
  ui/search_engines/search_engine_tab_helper.cc script that is triggered when
  handling URLs for OpenSearch descriptor.

  - An unspecified out-of-bounds read flaw in Blink.

  - A flaw related to WebSocket connections as HSTS
  (HTTP Strict Transport Security) is not enforced.

  - A type confusion flaw in the 'ReduceTransitionElementsKind' function in
  hydrogen-check-elimination.cc script related to HTransitionElementsKind
  handling.

  - A Tap-Jacking flaw that is triggered as certain synthetic Tap events aren't
  preceded by TapDown events.

  - An unspecified out-of-bounds read flaw in WebGL related to handling of ES3
  commands.

  - An unspecified out-of-bounds write flaw in Skia.

  - A use-after-free error in content/renderer/render_frame_impl.cc script.

  - A flaw in the 'MediaElementAudioSourceNode::process' function in
  modules/webaudio/MediaElementAudioSourceNode.cpp script.

  - An unspecified flaw in the HTML Parser.

  - Multiple unspecified Vulnerabilities

  - Browser does not confirm with the user before setting
  CONTENT_SETTINGS_TYPE_FULLSCREEN and CONTENT_SETTINGS_TYPE_MOUSELOCK.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions, conduct row-hammer attacks,
  obtain sensitive data, trigger unintended UI actions via crafted dimension,
  cause a denial of service and other unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  42.0.2311.90 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  42.0.2311.90 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/04/stable-channel-update_14.html");

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

if(version_is_less(version:chromeVer, test_version:"42.0.2311.90"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     42.0.2311.90'  + '\n';
  security_message(data:report);
  exit(0);
}
