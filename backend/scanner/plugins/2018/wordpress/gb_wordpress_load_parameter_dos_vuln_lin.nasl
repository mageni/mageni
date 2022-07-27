###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress 'load-scripts.php' Denial of Service Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812693");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6389");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-05 20:23:28 +0530 (Mon, 05 Feb 2018)");
  script_name("WordPress 'load-scripts.php' Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the file 'load-scripts.php'
  do not require any authentication and file selectively calls required JavaScript
  files by passing their names into the 'load' parameter, separated by a comma.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial of service condition on affected system.");

  script_tag(name:"affected", value:"WordPress versions 4.9.2 and prior on Linux");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  # nb: Seems it won't be fixed by WP according to: https://wordpress.org/support/topic/does-wordfence-patch-dos-issue-cve-2018-6389-automatically/
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://thehackernews.com/2018/02/wordpress-dos-exploit.html");
  script_xref(name:"URL", value:"https://baraktawily.blogspot.in/2018/02/how-to-dos-29-of-world-wide-websites.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if (!wordPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:wordPort, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if (version_is_less_equal(version:vers, test_version:"4.9.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(data:report, port:path);
  exit(0);
}

exit(0);
