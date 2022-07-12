###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mult_vuln_aug15_lin.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apache HTTP Server Multiple Vulnerabilities August15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806018");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3185", "CVE-2015-3183");
  script_bugtraq_id(75965, 75963);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-14 12:49:14 +0530 (Fri, 14 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server Multiple Vulnerabilities August15 (Linux)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - an error in 'ap_some_auth_required' function in 'server/request.c'
  script which does not consider that a Require directive may be associated with
  an authorization setting rather than an authentication setting.

  - an error in chunked transfer coding implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass intended access restrictions in opportunistic
  circumstances and to cause cache poisoning or credential hijacking if an
  intermediary proxy is in use.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.x before
  2.4.14 on linux.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.14 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}

if(version_in_range(version:httpd_ver, test_version:"2.4", test_version2:"2.4.13"))
{
  report = 'Installed version: ' + httpd_ver + '\n' +
           'Fixed version:     ' + "2.4.14" + '\n';
  security_message(data:report, port:httpd_port);
  exit(0);
}

