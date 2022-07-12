###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_39013.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL 'ssl3_get_record()' Remote Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100587");
  script_version("$Revision: 13898 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
  script_bugtraq_id(39013);
  script_cve_id("CVE-2010-0740");

  script_name("OpenSSL 'ssl3_get_record()' Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39013");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata45.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata46.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata47.html");
  script_xref(name:"URL", value:"http://www.openssl.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510726");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20100324.txt");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "gb_openssl_detect_win.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial-of-service vulnerability caused
  by a NULL-pointer dereference.");

  script_tag(name:"vuldetect", value:"According to its banner the remote Webserver is using a version prior
  to OpenSSL 0.9.8n which is vulnerable.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"OpenSSL versions 0.9.8f through 0.9.8m are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if(version_in_range(version:vers, test_version:"0.9.8f", test_version2:"0.9.8m")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8n", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);