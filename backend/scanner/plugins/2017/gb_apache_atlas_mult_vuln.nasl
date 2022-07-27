##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_atlas_mult_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Apache Atlas Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:apache:atlas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112031");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-3150", "CVE-2017-3151", "CVE-2017-3152", "CVE-2017-3153", "CVE-2017-3154", "CVE-2017-3155");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-31 14:16:09 +0200 (Thu, 31 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Atlas Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apache Atlas and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Atlas versions 0.6.0-incubating and 0.7.0-incubating are vulnerable.");

  script_tag(name:"solution", value:"Update to 0.7.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/4a4fef91e067fd0d9da569e30867c1fa65e2a0520acde71ddefee0ea@%3Cdev.atlas.apache.org%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_detect.nasl");
  script_mandatory_keys("Apache/Atlas/Installed");
  script_require_ports("Services/www", 21000);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(! port = get_app_port(cpe:CPE)) exit(0);
if(! vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_equal(version:vers, test_version:"0.6.0") || version_is_equal(version:vers, test_version:"0.7.0")) {
  vuln = TRUE;
  fix = "0.7.1";
}

if(vuln)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);
