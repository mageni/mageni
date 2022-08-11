###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_543_open_redirect_vuln.nasl 12637 2018-12-04 08:36:44Z mmartin $
#
# vBulletin 5.x < 5.4.4 Open Redirect Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112418");
  script_version("$Revision: 12637 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:36:44 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-08 09:07:22 +0100 (Thu, 08 Nov 2018)");

  script_cve_id("CVE-2018-15493");

  script_name("vBulletin 5.x < 5.4.4 Open Redirect Vulnerability");

  script_tag(name:"summary", value:"This host is installed with vBulletin and is
  prone to open-redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any value of the GET parameter 'url' is accepted as the target of a
  redirection. This can make phishing attacks much more credible.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to redirect users to arbitrary web sites and conduct phishing attacks.");
  script_tag(name:"affected", value:"vBulletin versions 5.x before 5.4.4.");

  script_tag(name:"solution", value:"Update vBulletin to version 5.4.4.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2018-017.txt");

  exit(0);
}

CPE = "cpe:/a:vbulletin:vbulletin";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(vers =~ "^5\.[0-4]\." && version_is_less(version:vers, test_version:"5.4.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);