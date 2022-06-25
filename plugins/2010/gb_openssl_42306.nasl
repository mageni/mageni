###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_42306.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL 'ssl3_get_key_exchange()' Use-After-Free Memory Corruption Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.100751");
  script_version("$Revision: 13898 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_bugtraq_id(42306);
  script_cve_id("CVE-2010-2939");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("OpenSSL 'ssl3_get_key_exchange()' Use-After-Free Memory Corruption Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42306");
  script_xref(name:"URL", value:"http://www.openssl.org");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Aug/84");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "gb_openssl_detect_win.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"summary", value:"OpenSSL is prone to a remote memory-corruption vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to execute
  arbitrary code in the context of the application using the vulnerable library. Failed exploit attempts
  will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"The issue affects OpenSSL 1.0.0a. Other versions may also be affected.");

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

if(version_is_equal(version:vers, test_version:"1.0.0a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);