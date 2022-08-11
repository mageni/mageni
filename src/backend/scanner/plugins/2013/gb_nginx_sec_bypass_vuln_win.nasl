##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_sec_bypass_vuln_win.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx Security Bypass Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803222");
  script_version("$Revision: 13859 $");
  script_cve_id("CVE-2011-4963");
  script_bugtraq_id(55920);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-02-01 13:21:59 +0530 (Fri, 01 Feb 2013)");

  script_name("nginx Security Bypass Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50912");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/77244");
  script_xref(name:"URL", value:"http://english.securitylab.ru/lab/PT-2012-06");
  script_xref(name:"URL", value:"http://nginx.org/en/security_advisories.html");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2012/000086.html");
  script_xref(name:"URL", value:"http://blog.ptsecurity.com/2012/06/vulnerability-in-nginx-eliminated.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain unauthorized access to
  restricted resources via specially crafted HTTP requests containing NTFS extended attributes.");

  script_tag(name:"affected", value:"nginx versions 0.7.52 through 1.2.0 and 1.3.0 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error when processing HTTP requests for resources
  defined via the 'location' directive.");

  script_tag(name:"solution", value:"Upgrade to nginx version 1.3.1 or 1.2.1 or later.");

  script_tag(name:"summary", value:"This host is running nginx and is prone to security bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version:"0.7.52", test_version2:"1.2.0") ||
    version_is_equal(version:version, test_version:"1.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
