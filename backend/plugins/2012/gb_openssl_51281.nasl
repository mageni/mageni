###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_51281.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:openssl:openssl";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103394");
  script_bugtraq_id(51281);
  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_version("$Revision: 13898 $");

  script_name("OpenSSL Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51281");
  script_xref(name:"URL", value:"http://www.openssl.org");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20120104.txt");

  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-01-20 11:28:16 +0100 (Fri, 20 Jan 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "gb_openssl_detect_win.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSL prone to multiple security vulnerabilities.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to obtain sensitive information,
  cause a denial-of-service condition and perform unauthorized actions.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(vers =~ "1\.0\." && version_is_less(version:vers, test_version:"1.0.0f")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.0f", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(vers =~ "0\.9\." && version_is_less(version:vers, test_version:"0.9.8s")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8s", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);