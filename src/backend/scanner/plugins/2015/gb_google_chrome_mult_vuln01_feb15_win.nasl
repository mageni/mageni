###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_feb15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 Feb15 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805449");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1212", "CVE-2015-1211", "CVE-2015-1210", "CVE-2015-1209");
  script_bugtraq_id(72497);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-10 18:10:13 +0530 (Tue, 10 Feb 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Multiple Vulnerabilities-01 Feb15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple unspecified vulnerabilities in Google Chrome.

  - The 'OriginCanAccessServiceWorkers' function in
    content/browser/service_worker/service_worker_dispatcher_host.cc script
    does not properly restrict the URI scheme during a ServiceWorker
    registration.

  - The 'V8ThrowException::createDOMException' function in
    bindings/core/v8/V8ThrowException.cpp script in the V8 bindings in Blink
    does not properly consider frame access restrictions during the throwing
    of an exception.

  - A use-after-free flaw in the 'VisibleSelection::nonBoundaryShadowTreeRootNode'
    function in editing/VisibleSelection.cpp script is triggered when a selection's
    anchor is a shadow root");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers gain elevated privileges, bypass cross-origin policies, to cause a
  denial of service or possibly have unspecified other impact via different
  crafted dimensions.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  40.0.2214.111 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  40.0.2214.111 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/02/stable-update.html");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"40.0.2214.111"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
             'Fixed version:     40.0.2214.111'  + '\n';
  security_message(data:report);
  exit(0);
}
