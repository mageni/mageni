###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bozotic_http_server_dos_vuln.nasl 14165 2019-03-14 06:59:37Z cfischer $
#
# bozotic HTTP server Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:eterna:bozohttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801245");
  script_version("$Revision: 14165 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 07:59:37 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2010-2195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("bozotic HTTP server Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_bozotic_http_server_detect.nasl");
  script_mandatory_keys("bozohttpd/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40737");
  script_xref(name:"URL", value:"http://www.eterna.com.au/bozohttpd/CHANGES");
  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2010-2195");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service
  via vectors related to a 'wrong code generation interaction with GCC'.");

  script_tag(name:"affected", value:"bozotic HTTP server (aka bozohttpd) version 20090522 through 20100512.");

  script_tag(name:"insight", value:"The flaw is due to vectors related to a 'wrong code generation
  interaction with GCC'.");

  script_tag(name:"solution", value:"Upgrade to bozotic HTTP server version 20100621 or later.");

  script_tag(name:"summary", value:"This host is running bozotic HTTP server and is prone to Denial of
  Service Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(port:port, cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"20090522", test_version2:"20100512")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20100621");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);