###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_mul_vuln_jun_2017.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Kodi Multiple Vulnerabilities June 2017 (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:kodi:kodi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107276");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 14:23:07 +0100 (Thu, 14 Dec 2017)");
  script_cve_id("CVE-2017-8314");
  script_bugtraq_id(98668);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Kodi Multiple Vulnerabilities June 2017 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kodi_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Kodi/WebServer/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98668");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201706-17");

  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in Kodi, the worst
  of which could allow remote attackers to execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers may use a specially crafted request with
  directory-traversal sequences (&#39 ../&#39 ) to retrieve sensitive information and modify
  arbitrary files. This may aid in further attacks.");

  script_tag(name:"impact", value:"A remote attacker could entice a user to open a specially
  crafted image file using Kodi, possibly resulting in a Denial of Service condition.
  Furthermore, a remote attacker could entice a user process a specially crafted ZIP file
  containing subtitles using Kodi, possibly resulting in execution of arbitrary code with
  the privileges of the process or a Denial of Service condition.");

  script_tag(name:"affected", value:"Kodi 17.1 and prior versions are vulnerable");

  script_tag(name:"solution", value:"Update to Kodi 17.2 or a later version.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"17.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"17.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
