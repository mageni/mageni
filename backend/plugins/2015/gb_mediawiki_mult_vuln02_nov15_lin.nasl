###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln02_nov15_lin.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# MediaWiki Multiple Vulnerabilities -02 Nov15 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806633");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472");
  script_bugtraq_id(65003);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-26 16:46:38 +0530 (Thu, 26 Nov 2015)");
  script_name("MediaWiki Multiple Vulnerabilities -02 Nov15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with MediaWiki
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error which displays some information about deleted pages in the log
  API, enhanced RecentChanges, and user watchlists.

  - An error in CSS whose sanitization did not filter -o-link attributes.

  - An error leading SVG sanitization to bypass when the XML was considered
  invalid.

  - An error in SVG files upload that could lead to include external stylesheets
  in upload.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.19.10, 1.2x before 1.21.4,
  and 1.22.x before 1.22.1 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 1.19.10 or 1.21.4 or
  1.22.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000138.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl", "secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mediawiki.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!http_ver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_is_less(version:http_ver, test_version:"1.19.10"))
{
  fix = "1.19.10";
  VULN = TRUE ;
}

else if(version_in_range(version:http_ver, test_version:"1.20", test_version2:"1.21.3"))
{
  fix = "1.21.4";
  VULN = TRUE ;
}

else if(version_is_equal(version:http_ver, test_version:"1.22.0"))
{
  fix = "1.22.1";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + http_ver + '\n' +
           'Fixed version:     ' + fix      + '\n';
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);