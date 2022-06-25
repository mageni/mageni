##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2019-01)-MAC OS X
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814833");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-5754", "CVE-2019-5782", "CVE-2019-5755", "CVE-2019-5756",
                "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760",
                "CVE-2019-5761", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764",
                "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768",
                "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772",
                "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776",
                "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780",
                "CVE-2019-5781");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-30 12:34:14 +0530 (Wed, 30 Jan 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2019-01)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to

  - Inappropriate implementation in QUIC Networking and V8.

  - Insufficient policy enforcement in the browser, Omnibox, ServiceWorker,
    Extensions, Canvas and DevTools.

  - Insufficient validation of untrusted input in SafeBrowsing, V8 and Blink.

  - Use after free errors in PDFium, Blink, HTML, SwiftShader, WebRTC, FileAPI,
    Mojo interface and Payments.

  - A type confusion error in SVG.

  - Incorrect security UI in WebAPKs.

  - Heap buffer overflow errors in WebGL and SwiftShader");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to overflow the buffer, inject arbitrary code and conduct spoofing attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 72.0.3626.81 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  72.0.3626.81 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/01/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.google.com/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"72.0.3626.81"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"72.0.3626.81", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
