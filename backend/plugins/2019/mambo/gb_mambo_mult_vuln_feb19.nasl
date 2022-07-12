# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112521");
  script_version("$Revision: 13913 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 17:43:39 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-26 12:29:11 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2013-2562", "CVE-2013-2563", "CVE-2013-2564", "CVE-2013-2565");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Mambo CMS <= 4.6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mambo_detect.nasl");
  script_mandatory_keys("mambo_cms/detected");

  script_tag(name:"summary", value:"Mambo CMS is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Mambo CMS stores the MySQL database password in cleartext in the document root (CVE-2013-2562).

  - Mambo CMS uses world-readable permissions on configuration.php (CVE-2013-2563).

  - Mambo CMS allows remote attackers to cause a denial of service (memory and bandwidth consumption)
  by uploading a crafted file (CVE-2013-2564).

  - A vulnerability in Mambo CMS where the scripts thumbs.php, editorFrame.php, editor.php, images.php,
  manager.php discloses the root path of the webserver (CVE-2013-2565).");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a denial of service
  or obtain the root path of the webserver. Furthermore an authenticated attacker would be able to obtain the
  admin password hash by reading the configuration.php file or obtain sensitive information via unspecified vectors.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Mambo CMS through version 4.6.5.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/108462/mambocms465-permdosdisclose.txt");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/689");
  script_xref(name:"URL", value:"http://www.vapid.dhs.org/advisories/mambo_cms_4.6.5.html");
  script_xref(name:"URL", value:"http://www.vapidlabs.com/advisory.php?v=75");

  exit(0);
}

CPE = "cpe:/a:mambo-foundation:mambo";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less_equal(version: vers, test_version: "4.6.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "WillNotFix");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
