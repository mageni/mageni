###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_wicket_csrf_detect_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Wicket CSRF Detection Vulnerability
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

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112077");
  script_version("$Revision: 11983 $");

  script_cve_id("CVE-2016-6806");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-10 15:26:12 +0200 (Tue, 10 Oct 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Wicket CSRF Detection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Wicket
  and is prone to a vulnerability affecting the cross-site request forgery (CSRF) detection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected versions of Apache Wicket provide a CSRF prevention
      measure that fails to discover some cross origin requests");

  script_tag(name:"affected", value:"Apache Wicket 6.20.0, 6.21.0, 6.22.0, 6.23.0, 6.24.0, 7.0.0,
      7.1.0, 7.2.0, 7.3.0, 7.4.0 and 8.0.0-M1");

  script_tag(name:"solution", value:"6.x users should upgrade to 6.25.0, 7.x users should upgrade to
      7.5.0 and 8.0.0-M1 users should upgrade to 8.0.0-M2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/074b72585f4b7c6adda1af52aecbfe1be23c6d6f5bb9382270f059cd@%3Cannounce.apache.org%3E");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://wicket.apache.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(ver =~ "^(6\.)")
{
  if(version_is_less(version:ver, test_version:"6.25.0")){
    fix = "6.25.0";
  }
}
else if(ver =~ "^(7\.)")
{
  if(version_is_less(version:ver, test_version:"7.5.0")){
    fix = "7.5.0";
  }
}
else if(ver =~ "^(8\.)")
{
  if(version_is_equal(version:ver, test_version:"8.0.0-M1")){
    fix = "8.0.0-M2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:ver, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
