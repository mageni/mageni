###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_nov15_lin.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# MediaWiki Multiple Vulnerabilities - Nov15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806626");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-8005", "CVE-2015-8004", "CVE-2015-8003", "CVE-2015-8002",
                "CVE-2015-8001");
  script_bugtraq_id(77378, 77375, 77374, 77372);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-25 16:45:17 +0530 (Wed, 25 Nov 2015)");
  script_name("MediaWiki Multiple Vulnerabilities - Nov15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with MediaWiki
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - the chunked upload API (ApiUpload) which does not restrict the uploaded
  data to the claimed file size.

  - an error in the application which does not throttle file uploads.

  - improper restrict access to revisions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack, gain privileged access and
  have some other unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.23.11, 1.24.x before
  1.24.4, and 1.25.x before 1.25.3 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 1.23.11 or 1.24.4
  or 1.25.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1034028");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-October/000181.html");
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

if(version_is_less(version:http_ver, test_version:"1.23.11"))
{
  fix = "1.23.11";
  VULN = TRUE ;
}

else if(version_in_range(version:http_ver, test_version:"1.24.0", test_version2:"1.24.3"))
{
  fix = "1.24.4";
  VULN = TRUE ;
}

else if(version_in_range(version:http_ver, test_version:"1.25.0", test_version2:"1.25.3"))
{
  fix = "1.25.3";
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