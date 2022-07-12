###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_38562.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL 'bn_wexpend()' Error Handling Unspecified Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100527");
  script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_bugtraq_id(38562);
  script_cve_id("CVE-2009-3245");
  script_version("$Revision: 13898 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("OpenSSL 'bn_wexpend()' Error Handling Unspecified Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38562");
  script_xref(name:"URL", value:"http://openssl.org/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "gb_openssl_detect_win.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more
  information.");

  script_tag(name:"summary", value:"OpenSSL is prone to an unspecified vulnerability in bn_wexpend().");

  script_tag(name:"affected", value:"OpenSSL versions prior to OpenSSL 0.9.8m are vulnerable.");

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

if(vers =~ "^0\.9\." && version_is_less(version:vers , test_version:"0.9.8m")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8m", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);