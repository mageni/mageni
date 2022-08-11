###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuuo_nvr_backdoor_active.nasl 12767 2018-12-12 08:39:09Z asteins $
#
# NUUO NVR < 3.9.1 Backdoor Activated
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:nuuo:nuuo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141487");
  script_version("$Revision: 12767 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 09:39:09 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-09-18 10:28:22 +0700 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-1150");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NUUO NVR < 3.9.1 Backdoor Activated");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");

  script_tag(name:"summary", value:"The Backdoor in NUUO NVR is active.");

  script_tag(name:"insight", value:"If the file '/tmp/moses' is present on the device unauthenticated remote
attacker can list all of the non-admin users and change their passwords");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the backdoor is active.");

  script_tag(name:"solution", value:"Update to version 3.9.1 (03.09.0001.0000) or later. Remove the file
'/tmp/moses' from the system. Recheck if malicious users have been added and change all passwords.");

  script_xref(name:"URL", value:"https://www.nuuo.com/NewsDetail.php?id=0425");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2018-25");
  script_xref(name:"URL", value:"https://www.tenable.com/blog/tenable-research-advisory-peekaboo-critical-vulnerability-in-nuuo-network-video-recorder");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/users_xml.php';
if (http_vuln_check(port: port, url: url, pattern: "<AccountInfo>", check_header: TRUE)) {
  report = 'The backdoor seems to be activated since an unauthenticated request to ' +
           report_vuln_url(port: port, url: url, url_only: TRUE) + ' returns information about all non-admin' +
           ' users.';
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
