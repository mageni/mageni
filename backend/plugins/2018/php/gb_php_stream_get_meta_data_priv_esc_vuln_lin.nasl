###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_stream_get_meta_data_priv_esc_vuln_lin.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# PHP 'stream_get_meta_data' Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812512");
  script_version("$Revision: 12120 $");
  script_cve_id("CVE-2016-10712");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 12:02:20 +0530 (Tue, 20 Feb 2018)");
  script_name("PHP 'stream_get_meta_data' Privilege Escalation Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the function
  stream_get_meta_data of the component File Upload. The manipulation as part
  of a Return Value leads to a privilege escalation vulnerability (Metadata).");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker
  to update the 'metadata' and affect on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"PHP versions before 5.5.32, 7.0.x before
  7.0.3, and 5.6.x before 5.6.18 on Linux.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.32, 7.0.3,
  or 5.6.18 or later.");

  script_xref(name:"URL", value:"https://vuldb.com/?id.113055");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71323");
  script_xref(name:"URL", value:"https://git.php.net/?p=php-src.git;a=commit;h=6297a117d77fa3a0df2e21ca926a92c231819cd5");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

if(version_is_less(version:phpVers, test_version:"5.5.32")){
  fix = "5.5.32";
}

else if(version_in_range(version:phpVers, test_version:"7.0.0", test_version2:"7.0.2")){
  fix = "7.0.3";
}

else if(phpVers =~ "^5\.6" && version_is_less(version:phpVers, test_version:"5.6.18")){
  fix = "5.6.18";
}

if(fix)
{
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}
exit(0);
