###############################################################################
# OpenVAS Vulnerability Test
#
# Tiki Wiki Multiple Vulnerabilities Feb18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812811");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-7302", "CVE-2018-7303", "CVE-2018-7304");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-23 12:13:22 +0530 (Fri, 23 Feb 2018)");
  script_name("Tiki Wiki Multiple Vulnerabilities Feb18");

  script_tag(name:"summary", value:"The host is installed with Tiki Wiki CMS
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The CMS allows upload of .PNG file which is actually having SVG content without
    checking.

  - The CMS does not validate the user input for special characters.

  - An input validation error in the 'Calendar' component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an
  attacker to perform a CSV Injection attack to perform malicious activity,
  XSS and HTML injection attack.");

  script_tag(name:"affected", value:"Tiki Wiki version 17.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://websecnerd.blogspot.in/2018/01/tiki-wiki-cms-groupware-17.html");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_equal(version:vers, test_version:"17.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(0);
